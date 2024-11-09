import os
import pandas as pd

# Directory where CSV files are located
logs_directory = './logs'

# List all CSV files in the directory
csv_files = [f for f in os.listdir(logs_directory) if f.endswith('.csv')]

# Initialize an empty list to hold dataframes
dataframes = []

# Load each CSV file into a dataframe and add it to the list
for file in csv_files:
    file_path = os.path.join(logs_directory, file)
    df = pd.read_csv(file_path)
    dataframes.append(df)

# Concatenate all dataframes into one large dataframe
merged_df = pd.concat(dataframes)

# Save the merged dataframe to a new CSV file
merged_df.to_csv('merged_logs.csv', index=False)

print('All CSV files have been successfully merged into merged_logs.csv')
