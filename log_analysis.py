import re
import csv

def analyze_log_file(log_file_path='sample.log', threshold=10):
    """
    Analyze log file to track IP requests, most accessed endpoint, 
    and detect suspicious login activities.
    
    :param log_file_path: Path to the log file to analyze
    :param threshold: Number of failed login attempts to consider an IP suspicious
    """
    # Patterns for IP and endpoint extraction
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # Matches IP addresses
    path_pattern = r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s([^\s]+)'  # Matches HTTP methods and resource paths
    failed_login_pattern = r'"POST\s/login\sHTTP/\S+"\s401'  # Identify failed login attempts with 401
    
    # Dictionaries to store analysis results
    ip_counts = {}
    endpoint_counts = {}
    failed_login_counts = {}
    
    # Process the log file
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                # Match IP addresses
                ip_match = re.search(ip_pattern, line)
                # Search for endpoint patterns
                path_search = re.search(path_pattern, line)
                failed_login_search = re.search(failed_login_pattern, line)
                
                # Count IP requests
                if ip_match:
                    ip_address = ip_match.group(1)
                    ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1
                
                # Count endpoint access
                if path_search:
                    endpoint = path_search.group(1)
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
                
                # Track failed login attempts
                if ip_match and failed_login_search:
                    failed_login_ip = ip_match.group(1)
                    failed_login_counts[failed_login_ip] = failed_login_counts.get(failed_login_ip, 0) + 1
        
        # Sort results
        sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_endpoint_counts = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Get the most accessed endpoint
        max_accessed_endpoint = sorted_endpoint_counts[0] if sorted_endpoint_counts else ('No Endpoint', 0)
        
        # Identify suspicious IPs
        suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count > threshold}
        
        # Save results to CSV
        save_results_to_csv(
            sorted_ip_counts, 
            max_accessed_endpoint, 
            suspicious_ips
        )
        
        # Display results in terminal
        display_terminal_results(
            sorted_ip_counts, 
            max_accessed_endpoint, 
            suspicious_ips
        )
    
    except FileNotFoundError:
        print(f"Error: Log file '{log_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def save_results_to_csv(ip_counts, max_endpoint, suspicious_ips):
    """
    Save analysis results to a CSV file.
    
    :param ip_counts: List of tuples (IP, request count)
    :param max_endpoint: Tuple of (most accessed endpoint, access count)
    :param suspicious_ips: Dictionary of suspicious IPs and their failed login attempts
    """
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Section 1: Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts:
            writer.writerow([ip, count])
        writer.writerow([])  # Blank line for separation
        
        # Section 2: Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(max_endpoint)
        writer.writerow([])  # Blank line for separation
        
        # Section 3: Detect Suspicious Activity
        writer.writerow(['Detect Suspicious Activity'])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])
    
    print("Results saved to log_analysis_results.csv")

def display_terminal_results(ip_counts, max_endpoint, suspicious_ips):
    """
    Display analysis results in the terminal.
    
    :param ip_counts: List of tuples (IP, request count)
    :param max_endpoint: Tuple of (most accessed endpoint, access count)
    :param suspicious_ips: Dictionary of suspicious IPs and their failed login attempts
    """
    # Display IP Address Analysis
    print("\nIP Address Analysis:")
    print(f"{'IP Address':<15}{'Request Count':<15}")
    print("-" * 30)
    for ip, count in ip_counts:
        print(f"{ip:<15}{count:<15}")
    
    # Display Most Accessed Endpoint
    print("\nMost Accessed Endpoint:")
    print(f"{'Endpoint':<30}{'Access Count':<15}")
    print("-" * 45)
    print(f"{max_endpoint[0]:<30}{max_endpoint[1]:<15}")
    
    # Display Suspicious Activity
    print("\nDetect Suspicious Activity:")
    print(f"{'IP Address':<30}{'Failed Login Count':<15}")
    print("-" * 45)
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<30}{count:<15}")
    else:
        print("No suspicious IPs detected")

# Main execution
if __name__ == "__main__":
    analyze_log_file()