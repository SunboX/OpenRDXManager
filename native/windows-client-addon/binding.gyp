{
  "targets": [
    {
      "target_name": "openrdx_windows_client",
      "sources": ["openrdx_windows_client.cc", "windows_log_files.cc", "windows_log_binding.cc", "windows_mcp_files.cc", "windows_private_rename.cc"],
      "conditions": [["OS=='win'", {
        "defines": ["UNICODE", "_UNICODE", "WIN32_LEAN_AND_MEAN", "NOMINMAX", "_WIN32_WINNT=0x0A00"],
        "libraries": ["advapi32.lib", "shell32.lib", "ole32.lib"],
        "msvs_settings": {
          "VCCLCompilerTool": {
            "AdditionalOptions": ["/std:c++20", "/W4", "/WX", "/EHsc"]
          }
        }
      }]]
    }
  ]
}
