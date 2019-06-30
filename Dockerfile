FROM python:3.7-alpine
RUN pip3 install threatspec
RUN apk update && apk add graphviz && rm -rf /var/cache/apk/*