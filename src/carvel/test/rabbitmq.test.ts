import { execYtt } from '../src/ytt';
import { findDeployment, findService, findConfigMap, findSecret } from '../src/k8s-helper';
import { BINDER_RABBIT_NAME } from '../src/constants';

describe('rabbitmq', () => {
  it('should have default settings', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: ['scdf.deploy.binder.type=rabbit']
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const rabbitDeployment = findDeployment(yaml, BINDER_RABBIT_NAME);
    expect(rabbitDeployment).toBeTruthy();
    expect(rabbitDeployment?.spec?.replicas).toBe(1);
    expect(rabbitDeployment?.spec?.template?.spec?.containers.find(c => c.name === BINDER_RABBIT_NAME)?.image).toEqual(
      'rabbitmq:3.9.5'
    );
    expect(rabbitDeployment?.spec?.template?.spec?.containers.map(c => c.ports?.map(cp => cp.containerPort))).toEqual([
      [5672]
    ]);
    expect(rabbitDeployment?.spec?.template?.spec?.containers.map(c => c.volumeMounts?.map(vm => vm.name))).toEqual([
      ['rabbitmq-config-volume']
    ]);
    expect(rabbitDeployment?.spec?.template?.spec?.volumes?.map(v => v.name)).toEqual(['rabbitmq-config-volume']);
    expect(
      rabbitDeployment?.spec?.template?.spec?.containers
        .find(c => c.name === BINDER_RABBIT_NAME)
        ?.env?.find(e => e.name === 'RABBITMQ_DEFAULT_USER')?.valueFrom?.secretKeyRef?.key
    ).toEqual('rabbitmq-user');
    expect(
      rabbitDeployment?.spec?.template?.spec?.containers
        .find(c => c.name === BINDER_RABBIT_NAME)
        ?.env?.find(e => e.name === 'RABBITMQ_DEFAULT_PASS')?.valueFrom?.secretKeyRef?.key
    ).toEqual('rabbitmq-password');

    const rabbitSecret = findSecret(yaml, BINDER_RABBIT_NAME);
    expect(rabbitSecret).toBeTruthy();
    const rabbitSecretData = rabbitSecret?.data || {};
    expect(rabbitSecretData['rabbitmq-user']).toBe('ZGF0YWZsb3c=');
    expect(rabbitSecretData['rabbitmq-password']).toBe('c2VjcmV0');

    const rabbitService = findService(yaml, BINDER_RABBIT_NAME);
    expect(rabbitService).toBeTruthy();
    expect(rabbitService?.spec?.ports).toHaveLength(1);
    expect(rabbitService?.spec?.ports?.map(sp => sp.port)).toEqual([5672]);

    const rabbitConfigMap = findConfigMap(yaml, `${BINDER_RABBIT_NAME}-config`);
    expect(rabbitConfigMap).toBeTruthy();
    const rabbitConf = rabbitConfigMap?.data ? rabbitConfigMap.data['rabbitmq.conf'] : '';
    expect(rabbitConf).toHaveLength(0);
  });

  it('should have config', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: ['scdf.deploy.binder.type=rabbit', 'scdf.deploy.binder.rabbit.config.key1=value1']
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const rabbitConfigMap = findConfigMap(yaml, `${BINDER_RABBIT_NAME}-config`);
    expect(rabbitConfigMap).toBeTruthy();
    const rabbitConf = rabbitConfigMap?.data ? rabbitConfigMap.data['rabbitmq.conf'] : '';
    expect(rabbitConf).toContain('key1 = value1');
  });

  it('should change image', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: [
        'scdf.deploy.binder.type=rabbit',
        'scdf.deploy.binder.rabbit.image.repository=fakerepo',
        'scdf.deploy.binder.rabbit.image.tag=faketag'
      ]
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const rabbitDeployment = findDeployment(yaml, BINDER_RABBIT_NAME);
    expect(rabbitDeployment).toBeTruthy();
    expect(rabbitDeployment?.spec?.replicas).toBe(1);
    expect(rabbitDeployment?.spec?.template?.spec?.containers.find(c => c.name === BINDER_RABBIT_NAME)?.image).toEqual(
      'fakerepo:faketag'
    );
  });

  it('should use image digest', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: [
        'scdf.deploy.binder.type=rabbit',
        'scdf.deploy.binder.rabbit.image.repository=fakerepo',
        'scdf.deploy.binder.rabbit.image.tag=faketag',
        'scdf.deploy.binder.rabbit.image.digest=fakedigest'
      ]
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const rabbitDeployment = findDeployment(yaml, BINDER_RABBIT_NAME);
    expect(rabbitDeployment).toBeTruthy();
    expect(rabbitDeployment?.spec?.replicas).toBe(1);
    expect(rabbitDeployment?.spec?.template?.spec?.containers.find(c => c.name === BINDER_RABBIT_NAME)?.image).toEqual(
      'fakerepo@fakedigest'
    );
  });

  it('should change user', async () => {
    const result = await execYtt({
      files: ['config/binder', 'config/values'],
      dataValueYamls: [
        'scdf.deploy.binder.type=rabbit',
        'scdf.deploy.binder.rabbit.image.repository=fakerepo',
        'scdf.deploy.binder.rabbit.image.tag=faketag',
        'scdf.deploy.binder.rabbit.username=user',
        'scdf.deploy.binder.rabbit.password=pass'
      ]
    });

    expect(result.success, result.stderr).toBeTruthy();
    const yaml = result.stdout;

    const rabbitSecret = findSecret(yaml, BINDER_RABBIT_NAME);
    expect(rabbitSecret).toBeTruthy();
    const rabbitSecretData = rabbitSecret?.data || {};
    expect(rabbitSecretData['rabbitmq-user']).toBe('user');
    expect(rabbitSecretData['rabbitmq-password']).toBe('pass');
  });
});
