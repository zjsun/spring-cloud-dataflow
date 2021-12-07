FROM bitnami/spring-cloud-dataflow:2.9.1
MAINTAINER datav.com

USER root
ENV TZ=Asia/Shanghai
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ENV LANG     C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL   C.UTF-8

USER 1001

COPY target/spring-cloud-dataflow-server-2.9.2-SNAPSHOT.jar /opt/bitnami/spring-cloud-dataflow/spring-cloud-dataflow.jar
