# Use the official Kali Linux image as the base
FROM kalilinux/kali-rolling

# Set the working directory to /home/ail-typo-squatting
WORKDIR /home/ail-typo-squatting

# Copy your installation scripts into the container
COPY install.sh /install.sh
COPY installapp.sh /installapp.sh

# Copy the domainlists folder to /home/ail-typo-squatting
COPY domainlists /home/ail-typo-squatting/domainlists

# Copy the crontab file to cron.d (for system-wide jobs)
COPY my-crontab /etc/cron.d/my-crontab

# Make the installation scripts executable
RUN chmod +x /install.sh /installapp.sh

# Run the installation scripts
RUN /install.sh && /installapp.sh

# Give the correct permissions to the cron file
RUN chmod 0644 /etc/cron.d/my-crontab

# Apply the cron job file to the crontab
RUN crontab /etc/cron.d/my-crontab

# Expose port 5000 internally and map it to port 80 externally
EXPOSE 5000

# Start cron service and your app from the correct directory
CMD service cron start && python3 /home/ail-typo-squatting/app.py & tail -f /dev/null
