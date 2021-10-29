import { execYtt } from '../src/ytt';
import 'jest-extended';
import { findService, findDeployment, findAnnotation, findAnnotations } from '../src/k8s-helper';
import {
  SCDF_SERVER_NAME,
  SKIPPER_NAME,
  DB_SKIPPER_NAME,
  DB_DATAFLOW_NAME,
  DEFAULT_REQUIRED_DATA_VALUES
} from '../src/constants';

describe('ordering', () => {
  it('should have correct kapp change ordering', async () => {
    const result = await execYtt({
      files: ['config'],
      dataValueYamls: [...DEFAULT_REQUIRED_DATA_VALUES, 'scdf.deploy.database.type=postgres']
    });
    expect(result.success).toBeTruthy();
    const yaml = result.stdout;

    const skipperService = findService(yaml, SKIPPER_NAME);
    const skipperDeployment = findDeployment(yaml, SKIPPER_NAME);
    const dataflowService = findService(yaml, SCDF_SERVER_NAME);
    const dataflowDeployment = findDeployment(yaml, SCDF_SERVER_NAME);
    const skipperDbService = findService(yaml, DB_SKIPPER_NAME);
    const dataflowDbService = findService(yaml, DB_DATAFLOW_NAME);

    expect(findAnnotation(skipperService, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/skipper');
    expect(findAnnotation(skipperDeployment, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/skipper');
    expect(findAnnotation(dataflowService, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/server');
    expect(findAnnotation(dataflowDeployment, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/server');
    expect(findAnnotation(skipperDbService, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/db');
    expect(findAnnotation(dataflowDbService, 'kapp.k14s.io/change-group')).toBe('scdf.tanzu.vmware.com/db');

    expect(findAnnotations(skipperService, 'kapp.k14s.io/change-rule')).toContainAnyValues([
      'upsert after upserting scdf.tanzu.vmware.com/db'
    ]);
    expect(findAnnotations(skipperDeployment, 'kapp.k14s.io/change-rule')).toContainAnyValues([
      'upsert after upserting scdf.tanzu.vmware.com/db'
    ]);
    expect(findAnnotations(dataflowService, 'kapp.k14s.io/change-rule')).toContainAnyValues([
      'upsert after upserting scdf.tanzu.vmware.com/db',
      'upsert after upserting scdf.tanzu.vmware.com/skipper'
    ]);
    expect(findAnnotations(dataflowDeployment, 'kapp.k14s.io/change-rule')).toContainAnyValues([
      'upsert after upserting scdf.tanzu.vmware.com/db',
      'upsert after upserting scdf.tanzu.vmware.com/skipper'
    ]);
  });
});
