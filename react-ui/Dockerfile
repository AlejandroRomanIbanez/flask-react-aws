# Use a lightweight base image with Nginx
FROM nginx:alpine

# Copy Nginx configuration file
COPY react-ui/nginx.conf /etc/nginx/nginx.conf

# Copy the pre-built React app into the Nginx directory
COPY react-ui/build/ /usr/share/nginx/html/

# Expose ports 80 and 443
EXPOSE 80
EXPOSE 443

# Command to run Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]
