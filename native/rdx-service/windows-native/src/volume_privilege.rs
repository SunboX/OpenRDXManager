// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed service-only volume-maintenance enrollment and thread-local use.
pub(crate) mod journal;
mod policy;
mod scope;

pub(crate) use policy::{has_service_right, set_service_right};
pub(crate) use scope::VolumePrivilege;

const RIGHT: &str = "SeManageVolumePrivilege";
