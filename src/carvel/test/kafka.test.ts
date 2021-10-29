import { execYtt } from '../src/ytt';
import { findService, findStatefulSet, statefulSetContainer, containerEnvValue } from '../src/k8s-helper';
import { BINDER_KAFKA_NAME } from '../src/constants';

describe('kafka', () => {
  it('should have default settings', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: ['scdf.deploy.binder.type=kafka']
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const kafkaZkSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSs).toBeTruthy();

    const kafkaZkSsContainer = statefulSetContainer(kafkaZkSs, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSsContainer?.image).toBe('confluentinc/cp-zookeeper:5.5.2');

    const kafkaZkClientService = findService(yaml, `${BINDER_KAFKA_NAME}-zk-client`);
    expect(kafkaZkClientService).toBeTruthy();

    const kafkaZkServerService = findService(yaml, `${BINDER_KAFKA_NAME}-zk-server`);
    expect(kafkaZkServerService).toBeTruthy();

    const kafkaBrokerSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSs).toBeTruthy();

    const kafkaBrokerSsContainer = statefulSetContainer(kafkaBrokerSs, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSsContainer?.image).toBe('confluentinc/cp-kafka:5.5.2');

    expect(containerEnvValue(kafkaBrokerSsContainer, 'KAFKA_ADVERTISED_LISTENERS')).toBe(
      'PLAINTEXT://kafka-broker:9092'
    );
    expect(containerEnvValue(kafkaBrokerSsContainer, 'KAFKA_ZOOKEEPER_CONNECT')).toBe('kafka-zk-client:2181');

    const kafkaBrokerService = findService(yaml, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerService).toBeTruthy();
  });

  it('should change images', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: [
        'scdf.deploy.binder.type=kafka',
        'scdf.deploy.binder.kafka.brokerImage.repository=fakerepo1',
        'scdf.deploy.binder.kafka.brokerImage.tag=faketag1',
        'scdf.deploy.binder.kafka.zkImage.repository=fakerepo2',
        'scdf.deploy.binder.kafka.zkImage.tag=faketag2'
      ]
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const kafkaZkSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSs).toBeTruthy();

    const kafkaZkSsContainer = statefulSetContainer(kafkaZkSs, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSsContainer?.image).toBe('fakerepo2:faketag2');

    const kafkaBrokerSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSs).toBeTruthy();

    const kafkaBrokerSsContainer = statefulSetContainer(kafkaBrokerSs, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSsContainer?.image).toBe('fakerepo1:faketag1');
  });

  it('should change images digests', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: [
        'scdf.deploy.binder.type=kafka',
        'scdf.deploy.binder.kafka.brokerImage.repository=fakerepo1',
        'scdf.deploy.binder.kafka.brokerImage.tag=faketag1',
        'scdf.deploy.binder.kafka.brokerImage.digest=fakedigest1',
        'scdf.deploy.binder.kafka.zkImage.repository=fakerepo2',
        'scdf.deploy.binder.kafka.zkImage.tag=faketag2',
        'scdf.deploy.binder.kafka.zkImage.digest=fakedigest2'
      ]
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const kafkaZkSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSs).toBeTruthy();

    const kafkaZkSsContainer = statefulSetContainer(kafkaZkSs, `${BINDER_KAFKA_NAME}-zk`);
    expect(kafkaZkSsContainer?.image).toBe('fakerepo2@fakedigest2');

    const kafkaBrokerSs = findStatefulSet(yaml, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSs).toBeTruthy();

    const kafkaBrokerSsContainer = statefulSetContainer(kafkaBrokerSs, `${BINDER_KAFKA_NAME}-broker`);
    expect(kafkaBrokerSsContainer?.image).toBe('fakerepo1@fakedigest1');
  });
});
