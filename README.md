# Log Analysis Script

## Overview
This Python script provides a comprehensive log file analysis tool that processes web server logs to extract valuable insights about IP requests, endpoint access, and potential suspicious activities.

## Features
- **IP Request Tracking**: 
  - Counts and ranks the number of requests from each unique IP address
  - Helps identify most active clients or potential traffic sources

- **Endpoint Analysis**:
  - Identifies the most accessed endpoint in the log file
  - Provides insights into the most popular resources or API endpoints

- **Suspicious Activity Detection**:
  - Tracks failed login attempts
  - Identifies IP addresses with multiple failed login attempts
  - Configurable threshold for suspicious activity detection

## Prerequisites
- Python 3.x
- Standard Python libraries (included in Python standard library)
  - `re` (Regular Expressions)
  - `csv` (CSV file handling)

## Installation
1. Ensure Python is installed on your system
2. Clone the repository:
   ```
   git clone https://github.com/yourusername/log-analysis-script.git
   cd log-analysis-script
   ```

## Usage
1. Place your log file in the same directory (default filename is `sample.log`)
2. Run the script using Python:
   ```
   python log_analysis.py
   ```

## Customization
- Modify the `threshold` parameter in `analyze_log_file()` to adjust the sensitivity of suspicious activity detection
- Change the input log file path by passing a different file path to the function

## Output
The script generates two types of output:
1. Terminal display of analysis results
2. CSV file `log_analysis_results.csv` with detailed findings

## Technical Details
- **Regular Expressions**: Used for parsing log file contents
  - IP address extraction
  - Endpoint and HTTP method identification
  - Failed login attempt detection

- **Key Functions**:
  - `analyze_log_file()`: Main analysis function
  - `save_results_to_csv()`: Exports analysis results to CSV
  - `display_terminal_results()`: Prints analysis results to console

