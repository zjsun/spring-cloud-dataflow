FROM bitnami/spring-cloud-dataflow-composed-task-runner:2.9.1
MAINTAINER datav.com

USER root
ENV TZ=Asia/Shanghai
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ENV LANG     C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL   C.UTF-8

USER 1001

ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} /opt/bitnami/spring-cloud-dataflow-composed-task-runner/scdf-composed-task-runner.jar
