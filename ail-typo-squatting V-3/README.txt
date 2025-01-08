#pls add domainlists to the domainlists folder and update the crontab file before running the command below

#install + run command
docker build -t typo .
docker run --name typo -p 80:5000
