# Elastic Defend Ransomware Protection Testing

## Summary

These scripts are intended to help users confirm that the ransomware protection endpoint feature on Windows is enabled, configured correctly, and operational within their environment.

## How it works

`mock_ransomware.py` is used to launch the ransomware testing script. It will create a new directory (`ransomware_tmp`) within the current working directory along with 
a set of sample files before launching `mock_ransomware.ps1`.

`mock_ransomware.ps1` contains file modification logic that simulates ransomware activity by encrypting the contents of the files created by `mock_ransomware.py`

To launch this test, simply launch a Python interpreter and pass in the Python script as the sole argument:

```
python mock_ransomware.py
```

If your environment is correctly configured, a ransomware detection or prevention alert (depending on your Windows endpoint policy configuration) will be generated and sent to Elasticsearch.
