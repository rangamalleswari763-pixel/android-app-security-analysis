# An Integrated Static and Dynamic Analysis Pipeline for Android Application Security Assessment

## 1. Project Overview

This repository contains the technical artefacts associated with an MSc Cyber Security dissertation titled **"An Integrated Static and Dynamic Analysis Pipeline for Android Application Security Assessment."**

The project investigates Android application security by combining selected static and dynamic analysis techniques. The practical investigation focuses on the DIVA (Damn Insecure and Vulnerable App) application, an intentionally vulnerable Android application tested within a controlled Android emulator environment.

The investigation uses different security tools to examine application configuration, runtime behaviour, local data handling and network activity. Python scripts and a dashboard are also used to organise and present selected evidence collected during testing.

The main purpose is to examine how static and dynamic analysis techniques can contribute to Android application security assessment and to identify the findings and limitations of the investigation.

## 2. Research Aim

The aim of this project is to investigate Android application security through the application of selected static and dynamic analysis techniques, using the DIVA application to examine security-related weaknesses and runtime observations.

## 3. Tools and Technologies

The following tools and technologies were used during the investigation.

| Tool | Purpose |
|---|---|
| Android Studio | Android development environment and emulator management |
| Android Emulator | Provides the controlled environment for executing DIVA |
| MobSF | Static APK analysis and identification of potential security weaknesses |
| Frida | Runtime instrumentation and monitoring of selected application logging activity |
| Android Debug Bridge (ADB) | Emulator communication and examination of application-related artefacts |
| Logcat | Observation of Android application and system log messages |
| Wireshark | Network packet inspection and traffic analysis |
| TShark | Command-line extraction and examination of network traffic information |
| Python | Evidence processing and dashboard development |

## 4. Investigation Methodology

The investigation followed a structured testing approach.

### 4.1 Environment Preparation

An Android emulator was configured using Android Studio. The DIVA application was installed and prepared for security testing.

### 4.2 Static Analysis

The DIVA APK was examined using Mobile Security Framework (MobSF). The analysis provided information about application permissions, exported components and potential security-related weaknesses.

### 4.3 Dynamic Analysis

Selected runtime activities were examined using Frida and Logcat. Frida instrumentation was used to monitor the `android.util.Log.e()` method and inspect selected logging messages.

### 4.4 Application Security Testing

Selected tests examined input validation, credential presentation, PIN processing and application data storage. ADB was used to access relevant application artefacts within the authorised testing environment.

### 4.5 Network Traffic Analysis

Network traffic was captured from the Android emulator and examined using Wireshark and TShark. The investigation considered observed protocols, DNS requests and communication patterns.

The captured traffic represents emulator-wide activity and was not conclusively attributed to the DIVA application.

### 4.6 Python Evidence Dashboard

Python scripts were developed to organise selected security observations and present relevant runtime and network information through a dashboard.

The dashboard is an evidence organisation and reporting artefact rather than an autonomous vulnerability detection system.

## 5. Repository Structure

The main project files are organised within the following directory:

```text
android-app-security-analysis/
│
├── MobileSecurityAnalysis/
│   ├── static-analysis/
│   ├── dynamic-analysis/
│   ├── network-analysis/
│   ├── scripts/
│   ├── evidence/
│   └── reports/
│
├── README.md
└── .gitignore
```

The directory names above describe the intended organisation. Refer to the actual repository contents for the available files and subdirectories.

## 6. Software Requirements

The investigation used the following software and tools:

- Windows environment with Android Studio.
- Android Emulator.
- Python.
- Mobile Security Framework (MobSF).
- Frida client and compatible Frida server.
- Android Debug Bridge (ADB).
- Wireshark and TShark.
- Required Python packages for the dashboard and evidence-processing scripts.

Specific package requirements and execution instructions should be checked against the project scripts and configuration files.

## 7. Access and Usage Instructions

The project artefacts are available through the following GitHub repository:

**Repository URL:**

https://github.com/rangamalleswari763-pixel/android-app-security-analysis

To access the project:

1. Open the GitHub repository using the link above.
2. Select the green **Code** button.
3. Choose **Download ZIP**, or clone the repository using Git.
4. Extract the downloaded project files.
5. Open the `MobileSecurityAnalysis` directory.
6. Review the available documentation and requirements before running the scripts.

The tools and scripts should be used within an authorised and controlled Android testing environment.

## 8. Investigation Areas

The practical investigation produced observations relating to:

- APK permissions and exported application components.
- Potential weaknesses identified through static analysis.
- Selected runtime logging activity.
- Application input validation and database behaviour.
- Credential presentation and local application data.
- Emulator network protocols and DNS activity.
- Organisation and presentation of collected security evidence.

Supporting reports, scripts and evidence are included in the project directory where available.

## 9. Project Limitations

The practical investigation focused on one Android application, DIVA, rather than conducting a comparative assessment of multiple applications.

The network capture included emulator-wide traffic, meaning that individual packets could not be conclusively attributed to DIVA. Some security tests were inconclusive, and the presence of a particular application feature or configuration was not automatically treated as proof of an exploitable vulnerability.

The Frida implementation monitored selected logging activity rather than providing comprehensive monitoring of all application APIs.

The Python dashboard organises and presents selected evidence. It was not designed or validated as an independent automated vulnerability detection system. No representative-user evaluation or labelled-dataset performance assessment was conducted.

These limitations were considered when interpreting the investigation results.

## 10. Ethical and Security Considerations

The investigation was conducted using an intentionally vulnerable Android application in a controlled testing environment.

The tools and techniques were used for academic security analysis. Sensitive information, private credentials, access tokens and unrelated personal data should not be included in publicly shared project materials.

Security testing should only be performed on applications and systems for which appropriate authorisation has been obtained.

## 11. Academic Project Information

**Programme:** MSc Cyber Security

**Institution:** University of Roehampton

**Project Title:** An Integrated Static and Dynamic Analysis Pipeline for Android Application Security Assessment

**Application Investigated:** DIVA (Damn Insecure and Vulnerable App)

**Project Focus:** Android application security assessment using selected static and dynamic analysis techniques.

---

This repository provides supporting technical materials for the dissertation and is intended to improve the transparency and reproducibility of the practical investigation.
