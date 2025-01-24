import pandas as pd  # Import pandas for data manipulation and analysis
import re  # Import re for regular expression-based pattern matching
import datetime  # Import datetime for date and time handling
import matplotlib.pyplot as plt  # Import Matplotlib for creating visualizations
import seaborn as sns  # Import Seaborn for advanced data visualizations

# Function to import the log file
def file_import(filename):
    try:
        with open(fName, "r") as f:  # Open the log file in read mode
            log_file = f.readlines()  # Read all lines from the file
            log_file = "".join(log_file)  # Combine all lines into a single string
            return log_file  # Return the string representation of the log
    except IOError:  # Handle cases where the file cannot be accessed
        print('ERROR: Opening file', fName, '\n')  # Print an error message
        exit()  # Exit the program if the file cannot be opened

# Function to parse the log file
def log_parsing(log_file, columns, pattern):
    matches = re.findall(pattern, log_file, flags=re.MULTILINE)  # Use regex to extract fields from the log file
    df_log = pd.DataFrame(matches, columns=columns)  # Create a DataFrame with extracted matches
    df_log.reset_index(inplace=True)  # Add an index column to the DataFrame
    return df_log  # Return the parsed DataFrame

# Function to process the log data (convert data types and formats)
def log_processing(df_log):
    df_log['timestamp'] = pd.to_datetime(  # Convert 'timestamp' column to datetime format
        df_log['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')  # Specify the datetime format for parsing
    df_log[['statusCode', 'size']] = df_log[['statusCode', 'size']].astype(int)  # Convert 'statusCode' and 'size' to integers
    return df_log  # Return the processed DataFrame

# Define the file path for the log file (Windows path with backslashes)
fName = "C:\\Users\\alhab\\Desktop\\access_log.txt"

# Define the regex pattern for parsing log entries
pattern = r'(\d+\.\d+\.\d+\.\d+) (.+) (.+) \[(.+)\] "(\w+) (.+)" (\d+) (\d+) "(.+)" "(.+)"'

# Define the column names corresponding to the regex pattern
columns = ["remoteHost", "userID", "username", "timestamp", "req_type", "request",
           "statusCode", "size", "referer", "agent"]

# Phase 1: Log parsing and preprocessing
log_file = file_import(fName)  # Import the log file
df_log = log_parsing(log_file, columns, pattern)  # Parse the log file into a structured DataFrame
df_log = log_processing(df_log)  # Process the parsed log data (e.g., type conversions)

# Test the DataFrame by printing a row and column data types
print(df_log.iloc[10], '\n')  # Print the 10th row of the DataFrame for verification
print(df_log.dtypes, '\n')  # Print the data types of each column for verification
print("-"*50)  # Print a separator line

# Phase 2: Log analysis tasks

# Filter events between two specific dates
start_date = pd.to_datetime('2005-03-14:00:00:00 -0500', format='%Y-%m-%d:%H:%M:%S %z')  # Define the start date
end_date = pd.to_datetime('2005-03-15:23:59:59 -0500', format='%Y-%m-%d:%H:%M:%S %z')  # Define the end date
mask = (df_log['timestamp'] >= start_date) & (df_log['timestamp'] <= end_date)  # Create a mask for the date range
flt_datetime = df_log.loc[mask]  # Apply the mask to filter the DataFrame
print("hosts between the range of date %s and %s:" % (start_date, end_date))  # Print the date range
print('number of resulting events: ', len(flt_datetime))  # Print the count of filtered events
print('first row: ', flt_datetime.iloc[0].tolist())  # Print the first row of the filtered data
print('last row: ', flt_datetime.iloc[-1].tolist())  # Print the last row of the filtered data
print("-"*50)  # Print a separator line

# Top 5 hosts by access frequency
filt_hostfreq = (df_log.groupby('remoteHost').size().nlargest(5).reset_index(name='count'))  # Group by 'remoteHost' and find top 5
print("top 5 hosts that frequently access the server sorted by number of accesses:")  # Print the result
print(filt_hostfreq)  # Display the top 5 hosts with access counts
print("-"*50)  # Print a separator line

# Count occurrences of each HTTP status code
status_freq_pd_df = (df_log['statusCode'].value_counts().reset_index())  # Count the frequency of each status code
status_freq_pd_df.columns = ['stat_code', 'count']  # Rename the columns
print("count of each status code appears in the log:")  # Print the count of status codes
print(status_freq_pd_df)  # Display the result
print("-"*50)  # Print a separator line

# Top 5 hosts with the highest number of 404 response codes
flt_statcode404 = df_log[df_log['statusCode'] == 404].groupby(['remoteHost']).count()['statusCode'].nlargest(5).reset_index(name='count')  
# Filter rows with status code 404 and find top 5
print("top 5 hosts with highest number of 404 response codes (sorted):")  # Print the result
print(flt_statcode404)  # Display the result
print("-"*50)  # Print a separator line

# Plot HTTP status code occurrences in a bar chart
print("plotting status code occurrences in a bar chart")  # Inform about the bar chart
sns.catplot(x='stat_code', y='count', data=status_freq_pd_df, kind='bar', order=status_freq_pd_df['stat_code'])  
# Create a bar chart for HTTP status codes
plt.show()  # Show the chart
print("-"*50)  # Print a separator line

# Visualize the appearance of 404 status codes (top 5 hosts)
print("visualizing appearance of 404 status codes (top 5 hosts)")  # Inform about the chart
sns.catplot(x='count', y='remoteHost', data=flt_statcode404, kind='bar', order=flt_statcode404['remoteHost'])  
# Create a horizontal bar chart for 404 errors by host
plt.title('Appearance of 404 status codes (top 5 hosts)')  # Add a title to the chart
plt.show()  # Show the chart
print("-"*50)  # Print a separator line
