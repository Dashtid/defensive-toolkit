# Nginx Dockerfile for Defensive Toolkit
# Minimal and secure Nginx image with custom configuration

FROM nginx:1.29-alpine

# Set metadata
LABEL maintainer="david.at.dashti@outlook.com"
LABEL description="Nginx reverse proxy for Defensive Toolkit API"
LABEL version="1.3.0"

# Install OpenSSL for certificate generation
RUN apk add --no-cache openssl

# Remove default configuration
RUN rm -f /etc/nginx/conf.d/default.conf

# Create directories
RUN mkdir -p /var/www/certbot \
    && mkdir -p /etc/nginx/ssl \
    && mkdir -p /var/log/nginx \
    && chown -R nginx:nginx /var/www/certbot /var/log/nginx

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create self-signed certificate if none exists
RUN if [ ! -f /etc/nginx/ssl/cert.pem ]; then \
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"; \
    fi

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

# Expose ports
EXPOSE 80 443

# Run as nginx user
USER nginx

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
