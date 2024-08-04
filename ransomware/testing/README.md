# Elastic Defend Ransomware Protection Testing

## Summary

These scripts are intended to help users confirm that the behavioral ransomware protection endpoint feature on Windows is enabled, configured correctly, and operational within their environment.

## How it works

`mock_ransomware.py` will create a new directory (`ransomware_tmp`) within the current working directory along with a set of sample files before launching `mock_ransomware.ps1`.

`mock_ransomware.ps1` simulates ransomware activity by encrypting the contents of the files created by `mock_ransomware.py`.

To begin this test, simply launch a Python interpreter and pass in the Python script as the sole argument:

```
python mock_ransomware.py
```

To avoid any issues with ransomware protection potentially filtering out the file activity that these scripts generate, please launch this script from either C:\ or the current user's desktop.

If your environment is correctly configured, a ransomware detection or prevention alert (depending on your Windows endpoint policy configuration) will be generated and sent to Elasticsearch.
