# A static-site nginx image for testing capsule. Build it, flatten it with
# `docker export`, and run the result with `capsule run --rootfs`; see README.md.
FROM nginx:1.27-alpine

# Our config replaces the stock one; it's written to run the same way under
# Docker and under rootless capsule.
COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/html/

EXPOSE 8080

# capsule doesn't read CMD yet (it doesn't parse image config), so the same
# command is passed explicitly there. Skip the base image's entrypoint script:
# it only rewrites the stock config's templates, which we don't use.
ENTRYPOINT []
CMD ["nginx"]
