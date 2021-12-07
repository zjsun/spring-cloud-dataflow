FROM bitnami/spring-cloud-dataflow:2.9.1
MAINTAINER datav.com

USER root
ENV TZ=Asia/Shanghai
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environment
RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf

USER 1001

COPY target/spring-cloud-dataflow-server-2.9.2-SNAPSHOT.jar /opt/bitnami/spring-cloud-dataflow/spring-cloud-dataflow.jar
