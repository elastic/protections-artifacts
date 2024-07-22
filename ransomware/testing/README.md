# Elastic Defend Ransomware Protection Testing

## Summary

These scripts are intended to help users confirm that the ransomware protection endpoint feature on Windows enabled and operational within their environment.

## How it works

`mock_ransomware.py` is used to launch the ransomware testing script. It will first create a new directory (`ransomware_tmp`) within the current working directory along with 
a set of sample files before proceeding to launch a PowerShell script: `mock_ransomware.ps1`.

`mock_ransomware.ps1` contains the file modification logic that simulates ransomware activity by encrypting the contens of the files created by `mock_ransomware.py`

To launch this test, simply launch a Python interpreter and pass in the Python script as the sole argument:

```
python mock_ransomware.py
```

If your environment is correctly configured, a ransomware detection or prevention alert (depending on your Windows endpoint policy configuration) will be generated and sent to Elasticsearch.
