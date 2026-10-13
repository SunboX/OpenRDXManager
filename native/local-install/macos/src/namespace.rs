// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed local launchd namespace and protected historical migration policy.

/// Only the dedicated local job or its exact-owned previous local name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registration {
    Local,
    Previous,
}

impl Registration {
    /// Return one compiled system label; no caller-selected launchd target is accepted.
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "system/com.openrdx.hardware.local",
            Self::Previous => "system/com.openrdx.hardware",
        }
    }

    /// Prove exact top-level standalone path/program and the selected fixed label.
    pub fn is_owned(self, evidence: &str) -> bool {
        let paths: Vec<&str> = evidence
            .lines()
            .filter_map(|line| line.strip_prefix("\tpath = "))
            .collect();
        let programs: Vec<&str> = evidence
            .lines()
            .filter_map(|line| line.strip_prefix("\tprogram = "))
            .collect();
        evidence.starts_with(&format!("{} = {{\n", self.label()))
            && paths == ["/Library/LaunchDaemons/com.openrdx.hardware.plist"]
            && programs == ["/Library/PrivilegedHelperTools/openrdx-hardware"]
    }
}

/// Select fixed owned jobs after the caller proves all protected historical targets.
pub fn removal_plan(
    history: bool,
    local: Option<&str>,
    previous: Option<&str>,
) -> Result<Vec<Registration>, String> {
    let mut result = Vec::new();
    if let Some(evidence) = local {
        if !history || !Registration::Local.is_owned(evidence) {
            return Err(
                "foreign registration occupies the dedicated local label; setup is disabled".into(),
            );
        }
        result.push(Registration::Local);
    }
    if history && previous.is_some_and(|evidence| Registration::Previous.is_owned(evidence)) {
        result.push(Registration::Previous);
    }
    Ok(result)
}

/// Recheck immediately before stopping only selected owned jobs under retained root leases.
pub fn quiesce_plan(
    plan: &[Registration],
    mut probe: impl FnMut(Registration) -> Result<Option<String>, String>,
    mut stop: impl FnMut(Registration) -> Result<(), String>,
) -> Result<(), String> {
    for registration in plan {
        if let Some(evidence) = probe(*registration)? {
            if registration.is_owned(&evidence) {
                stop(*registration)?;
            } else if *registration == Registration::Local {
                return Err("dedicated local registration changed before bootout".into());
            }
            // A replaced previous job is foreign, including smd registrations;
            // preserve it entirely and continue preparing the separate namespace.
        }
    }
    if probe(Registration::Local)?.is_some() {
        return Err("dedicated local label is occupied; payload replacement is refused".into());
    }
    if plan.contains(&Registration::Previous)
        && probe(Registration::Previous)?
            .is_some_and(|evidence| Registration::Previous.is_owned(&evidence))
    {
        return Err("previous owned local registration did not stop".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render actual launchctl standalone evidence without trusting a label alone.
    fn owned(label: &str) -> String {
        format!(
            "system/{label} = {{\n\tpath = /Library/LaunchDaemons/com.openrdx.hardware.plist\n\tprogram = /Library/PrivilegedHelperTools/openrdx-hardware\n}}"
        )
    }

    /// Protected previous local jobs migrate; foreign signed registrations remain untouched.
    #[test]
    fn old_owned_upgrade_and_foreign_preservation_require_distinct_namespaces() {
        let local = owned("com.openrdx.hardware.local");
        let previous = owned("com.openrdx.hardware");
        let foreign = "system/com.openrdx.hardware = {\n\tpath = (submitted by smd.554)\n\tprogram identifier = Contents/Library/LaunchServices/openrdx-hardware (mode: 2)\n}";
        assert_eq!(
            removal_plan(true, None, Some(&previous)).unwrap(),
            [Registration::Previous]
        );
        assert_eq!(
            removal_plan(true, Some(&local), Some(foreign)).unwrap(),
            [Registration::Local]
        );
        assert!(removal_plan(false, None, Some(foreign)).unwrap().is_empty());
        assert!(
            removal_plan(false, None, Some(&previous))
                .unwrap()
                .is_empty()
        );
        assert!(removal_plan(false, Some(&local), None).is_err());
        assert!(removal_plan(true, Some(&previous), None).is_err());
        assert!(
            removal_plan(
                true,
                Some(&local.replace(
                    "/Library/PrivilegedHelperTools/openrdx-hardware",
                    "/tmp/foreign"
                )),
                Some(foreign)
            )
            .is_err()
        );
    }

    /// Changed old signed registrations survive both pre-stop and post-stop rechecks.
    #[test]
    fn quiescence_preserves_old_foreign_reappearance_and_rejects_new_foreign() {
        let previous = owned("com.openrdx.hardware");
        let foreign = "system/com.openrdx.hardware = {\n\tpath = (submitted by smd.554)\n}";
        let mut stopped = Vec::new();
        quiesce_plan(
            &[Registration::Previous],
            |registration| {
                Ok(match registration {
                    Registration::Previous => Some(foreign.into()),
                    Registration::Local => None,
                })
            },
            |registration| {
                stopped.push(registration);
                Ok(())
            },
        )
        .unwrap();
        assert!(stopped.is_empty(), "foreign old job must never be stopped");
        let mut previous_probes = 0;
        quiesce_plan(
            &[Registration::Previous],
            |registration| {
                Ok(match registration {
                    Registration::Previous => {
                        previous_probes += 1;
                        Some(if previous_probes == 1 {
                            previous.clone()
                        } else {
                            foreign.into()
                        })
                    }
                    Registration::Local => None,
                })
            },
            |registration| {
                stopped.push(registration);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(stopped, [Registration::Previous]);
        stopped.clear();
        assert!(
            quiesce_plan(
                &[Registration::Local],
                |_| Ok(Some(foreign.into())),
                |registration| {
                    stopped.push(registration);
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(stopped.is_empty(), "foreign new job must never be stopped");
        assert!(
            quiesce_plan(
                &[],
                |_| Ok(Some(owned("com.openrdx.hardware.local"))),
                |_| Ok(())
            )
            .is_err()
        );
    }
    /// Owned bootout must succeed and absence must be proved before payload replacement.
    #[test]
    fn owned_migration_requires_successful_bootout_and_absent_jobs() {
        let plan = [Registration::Local, Registration::Previous];
        let mut probes = [0; 2];
        let mut stopped = Vec::new();
        quiesce_plan(
            &plan,
            |registration| {
                let index = usize::from(registration == Registration::Previous);
                probes[index] += 1;
                Ok((probes[index] == 1)
                    .then(|| owned(registration.label().strip_prefix("system/").unwrap())))
            },
            |registration| {
                stopped.push(registration);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(stopped, plan);
        assert!(
            quiesce_plan(
                &[Registration::Previous],
                |registration| Ok(
                    (registration == Registration::Previous).then(|| owned("com.openrdx.hardware"))
                ),
                |_| Ok(())
            )
            .is_err()
        );
        let failure = quiesce_plan(
            &[Registration::Previous],
            |_| Ok(Some(owned("com.openrdx.hardware"))),
            |_| Err("bootout rejected".into()),
        );
        assert_eq!(failure, Err("bootout rejected".into()));
    }
}
