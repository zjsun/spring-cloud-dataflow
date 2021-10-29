/*
 * Copyright 2015-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.dataflow.server.configuration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ForkJoinPool;

import javax.sql.DataSource;

import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.mockito.Mockito;

import org.springframework.batch.core.repository.dao.AbstractJdbcBatchMetadataDao;
import org.springframework.batch.item.database.support.DataFieldMaxValueIncrementerFactory;
import org.springframework.batch.item.database.support.DefaultDataFieldMaxValueIncrementerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.hateoas.HypermediaAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.transaction.TransactionManagerCustomizers;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.common.security.core.support.OAuth2TokenUtilsService;
import org.springframework.cloud.common.security.support.SecurityStateBean;
import org.springframework.cloud.dataflow.audit.repository.AuditRecordRepository;
import org.springframework.cloud.dataflow.audit.service.AuditRecordService;
import org.springframework.cloud.dataflow.audit.service.DefaultAuditRecordService;
import org.springframework.cloud.dataflow.completion.CompletionConfiguration;
import org.springframework.cloud.dataflow.completion.StreamCompletionProvider;
import org.springframework.cloud.dataflow.completion.TaskCompletionProvider;
import org.springframework.cloud.dataflow.configuration.metadata.ApplicationConfigurationMetadataResolver;
import org.springframework.cloud.dataflow.container.registry.ContainerRegistryService;
import org.springframework.cloud.dataflow.core.DefaultStreamDefinitionService;
import org.springframework.cloud.dataflow.core.Launcher;
import org.springframework.cloud.dataflow.core.StreamDefinitionService;
import org.springframework.cloud.dataflow.core.TaskPlatform;
import org.springframework.cloud.dataflow.registry.repository.AppRegistrationRepository;
import org.springframework.cloud.dataflow.registry.service.AppRegistryService;
import org.springframework.cloud.dataflow.registry.service.DefaultAppRegistryService;
import org.springframework.cloud.dataflow.registry.support.AppResourceCommon;
import org.springframework.cloud.dataflow.rest.support.jackson.ISO8601DateFormatWithMilliSeconds;
import org.springframework.cloud.dataflow.rest.support.jackson.Jackson2DataflowModule;
import org.springframework.cloud.dataflow.server.DockerValidatorProperties;
import org.springframework.cloud.dataflow.server.TaskValidationController;
import org.springframework.cloud.dataflow.server.config.DataflowMetricsProperties;
import org.springframework.cloud.dataflow.server.config.VersionInfoProperties;
import org.springframework.cloud.dataflow.server.config.apps.CommonApplicationProperties;
import org.springframework.cloud.dataflow.server.config.features.FeaturesProperties;
import org.springframework.cloud.dataflow.server.controller.AboutController;
import org.springframework.cloud.dataflow.server.controller.AppRegistryController;
import org.springframework.cloud.dataflow.server.controller.AuditRecordController;
import org.springframework.cloud.dataflow.server.controller.CompletionController;
import org.springframework.cloud.dataflow.server.controller.JobExecutionController;
import org.springframework.cloud.dataflow.server.controller.JobExecutionThinController;
import org.springframework.cloud.dataflow.server.controller.JobInstanceController;
import org.springframework.cloud.dataflow.server.controller.JobStepExecutionController;
import org.springframework.cloud.dataflow.server.controller.JobStepExecutionProgressController;
import org.springframework.cloud.dataflow.server.controller.RestControllerAdvice;
import org.springframework.cloud.dataflow.server.controller.RootController;
import org.springframework.cloud.dataflow.server.controller.RuntimeAppInstanceController;
import org.springframework.cloud.dataflow.server.controller.RuntimeAppsController;
import org.springframework.cloud.dataflow.server.controller.RuntimeStreamsController;
import org.springframework.cloud.dataflow.server.controller.StreamDefinitionController;
import org.springframework.cloud.dataflow.server.controller.StreamDeploymentController;
import org.springframework.cloud.dataflow.server.controller.StreamLogsController;
import org.springframework.cloud.dataflow.server.controller.StreamValidationController;
import org.springframework.cloud.dataflow.server.controller.TaskCtrController;
import org.springframework.cloud.dataflow.server.controller.TaskDefinitionController;
import org.springframework.cloud.dataflow.server.controller.TaskExecutionController;
import org.springframework.cloud.dataflow.server.controller.TaskPlatformController;
import org.springframework.cloud.dataflow.server.controller.TaskSchedulerController;
import org.springframework.cloud.dataflow.server.controller.TasksInfoController;
import org.springframework.cloud.dataflow.server.controller.ToolsController;
import org.springframework.cloud.dataflow.server.controller.assembler.AppRegistrationAssemblerProvider;
import org.springframework.cloud.dataflow.server.controller.assembler.DefaultAppRegistrationAssemblerProvider;
import org.springframework.cloud.dataflow.server.controller.assembler.DefaultStreamDefinitionAssemblerProvider;
import org.springframework.cloud.dataflow.server.controller.assembler.DefaultTaskDefinitionAssemblerProvider;
import org.springframework.cloud.dataflow.server.controller.assembler.StreamDefinitionAssemblerProvider;
import org.springframework.cloud.dataflow.server.controller.assembler.TaskDefinitionAssemblerProvider;
import org.springframework.cloud.dataflow.server.job.LauncherRepository;
import org.springframework.cloud.dataflow.server.registry.DataFlowAppRegistryPopulator;
import org.springframework.cloud.dataflow.server.repository.DataflowJobExecutionDao;
import org.springframework.cloud.dataflow.server.repository.DataflowTaskExecutionDao;
import org.springframework.cloud.dataflow.server.repository.DataflowTaskExecutionMetadataDao;
import org.springframework.cloud.dataflow.server.repository.JdbcDataflowJobExecutionDao;
import org.springframework.cloud.dataflow.server.repository.JdbcDataflowTaskExecutionDao;
import org.springframework.cloud.dataflow.server.repository.JdbcDataflowTaskExecutionMetadataDao;
import org.springframework.cloud.dataflow.server.repository.StreamDefinitionRepository;
import org.springframework.cloud.dataflow.server.repository.TaskDefinitionRepository;
import org.springframework.cloud.dataflow.server.repository.TaskDeploymentRepository;
import org.springframework.cloud.dataflow.server.service.LauncherService;
import org.springframework.cloud.dataflow.server.service.SchedulerService;
import org.springframework.cloud.dataflow.server.service.SchedulerServiceProperties;
import org.springframework.cloud.dataflow.server.service.StreamService;
import org.springframework.cloud.dataflow.server.service.StreamValidationService;
import org.springframework.cloud.dataflow.server.service.TaskDeleteService;
import org.springframework.cloud.dataflow.server.service.TaskExecutionCreationService;
import org.springframework.cloud.dataflow.server.service.TaskExecutionInfoService;
import org.springframework.cloud.dataflow.server.service.TaskExecutionService;
import org.springframework.cloud.dataflow.server.service.TaskJobService;
import org.springframework.cloud.dataflow.server.service.TaskSaveService;
import org.springframework.cloud.dataflow.server.service.TaskValidationService;
import org.springframework.cloud.dataflow.server.service.impl.AppDeploymentRequestCreator;
import org.springframework.cloud.dataflow.server.service.impl.ComposedTaskRunnerConfigurationProperties;
import org.springframework.cloud.dataflow.server.service.impl.DefaultLauncherService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultSchedulerService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultStreamService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultTaskDeleteService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultTaskExecutionInfoService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultTaskExecutionRepositoryService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultTaskExecutionService;
import org.springframework.cloud.dataflow.server.service.impl.DefaultTaskSaveService;
import org.springframework.cloud.dataflow.server.service.impl.TaskAppDeploymentRequestCreator;
import org.springframework.cloud.dataflow.server.service.impl.TaskConfigurationProperties;
import org.springframework.cloud.dataflow.server.service.impl.validation.DefaultStreamValidationService;
import org.springframework.cloud.dataflow.server.service.impl.validation.DefaultTaskValidationService;
import org.springframework.cloud.dataflow.server.stream.SkipperStreamDeployer;
import org.springframework.cloud.dataflow.server.stream.StreamDeployer;
import org.springframework.cloud.deployer.resource.maven.MavenProperties;
import org.springframework.cloud.deployer.resource.maven.MavenResourceLoader;
import org.springframework.cloud.deployer.resource.support.DelegatingResourceLoader;
import org.springframework.cloud.deployer.spi.app.AppDeployer;
import org.springframework.cloud.deployer.spi.core.RuntimeEnvironmentInfo;
import org.springframework.cloud.deployer.spi.scheduler.Scheduler;
import org.springframework.cloud.deployer.spi.task.TaskLauncher;
import org.springframework.cloud.skipper.client.SkipperClient;
import org.springframework.cloud.skipper.domain.AboutResource;
import org.springframework.cloud.skipper.domain.Dependency;
import org.springframework.cloud.skipper.domain.Deployer;
import org.springframework.cloud.task.configuration.TaskProperties;
import org.springframework.cloud.task.repository.TaskExplorer;
import org.springframework.cloud.task.repository.TaskRepository;
import org.springframework.cloud.task.repository.support.DatabaseType;
import org.springframework.cloud.task.repository.support.SimpleTaskRepository;
import org.springframework.cloud.task.repository.support.TaskExecutionDaoFactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.FileSystemResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.map.repository.config.EnableMapRepositories;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.hateoas.server.EntityLinks;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Michael Minella
 * @author Mark Fisher
 * @author Gunnar Hillert
 * @author Ilayaperumal Gopinathan
 * @author Christian Tzolov
 * @author Gunnar Hillert
 * @author David Turanski
 * @author Glenn Renfro
 */
@Configuration
@EnableSpringDataWebSupport
@Import({CompletionConfiguration.class})
@ImportAutoConfiguration({ HibernateJpaAutoConfiguration.class,
		JacksonAutoConfiguration.class,
		FlywayAutoConfiguration.class,
		HypermediaAutoConfiguration.class,
		RestTemplateAutoConfiguration.class })
@EnableWebMvc
@EnableConfigurationProperties({ CommonApplicationProperties.class,
		VersionInfoProperties.class,
		DockerValidatorProperties.class,
		TaskConfigurationProperties.class,
		TaskProperties.class,
		DockerValidatorProperties.class,
		DataflowMetricsProperties.class,
		ComposedTaskRunnerConfigurationProperties.class })
@EntityScan({
		"org.springframework.cloud.dataflow.registry.domain",
		"org.springframework.cloud.dataflow.core"
})
@EnableJpaRepositories(basePackages = {
		"org.springframework.cloud.dataflow.registry.repository",
		"org.springframework.cloud.dataflow.audit.repository",
		"org.springframework.cloud.dataflow.server.repository"
})
@EnableJpaAuditing
@EnableMapRepositories("org.springframework.cloud.dataflow.server.job")
@EnableTransactionManagement
public class TestDependencies extends WebMvcConfigurationSupport {

	@Bean
	public RestControllerAdvice restControllerAdvice() {
		return new RestControllerAdvice();
	}

	@Bean
	public Jackson2ObjectMapperBuilderCustomizer dataflowObjectMapperBuilderCustomizer() {
		return (builder) -> {
			builder.dateFormat(new ISO8601DateFormatWithMilliSeconds());
			builder.modules(new JavaTimeModule(), new Jackson2DataflowModule());
		};
	}

	@Bean
	public AuditRecordService auditRecordService(AuditRecordRepository auditRecordRepository) {
		return new DefaultAuditRecordService(auditRecordRepository);
	}

	@Bean
	public MavenProperties mavenProperties() {
		MavenProperties mavenProperties = new MavenProperties();
		mavenProperties.setRemoteRepositories(new HashMap<>(Collections.singletonMap("springRepo",
				new MavenProperties.RemoteRepository("https://repo.spring.io/libs-snapshot"))));
		return mavenProperties;
	}

	@Bean
	public DelegatingResourceLoader resourceLoader(MavenProperties mavenProperties) {
		Map<String, ResourceLoader> resourceLoaders = new HashMap<>();
		resourceLoaders.put("maven", new MavenResourceLoader(mavenProperties));
		resourceLoaders.put("file", new FileSystemResourceLoader());

		DelegatingResourceLoader delegatingResourceLoader = new DelegatingResourceLoader(resourceLoaders);
		return delegatingResourceLoader;
	}

	@Bean
	public AppResourceCommon appResourceService(MavenProperties mavenProperties,
			DelegatingResourceLoader delegatingResourceLoader) {
		return new AppResourceCommon(mavenProperties, delegatingResourceLoader);
	}

	@Bean
	public StreamDeploymentController updatableStreamDeploymentController(StreamDefinitionRepository repository,
			StreamService streamService, StreamDefinitionService streamDefinitionService) {
		return new StreamDeploymentController(repository, streamService, streamDefinitionService);
	}

	@Bean
	public StreamLogsController streamLogsController(StreamDeployer streamDeployer) {
		return new StreamLogsController(streamDeployer);
	}

	@Bean
	public TaskCtrController tasksCtrController(ApplicationConfigurationMetadataResolver metadataResolver,
			TaskConfigurationProperties taskConfigurationProperties,
			ComposedTaskRunnerConfigurationProperties composedTaskRunnerConfigurationProperties,
			AppResourceCommon appResourceCommon) {
		return new TaskCtrController(metadataResolver, taskConfigurationProperties,
				composedTaskRunnerConfigurationProperties, appResourceCommon);
	}

	@Bean
	public FeaturesProperties featuresProperties() {
		return new FeaturesProperties();
	}

	@Bean
	public StreamValidationService streamValidationService(AppRegistryService appRegistry,
			DockerValidatorProperties dockerValidatorProperties,
			StreamDefinitionRepository streamDefinitionRepository,
			StreamDefinitionService streamDefinitionService) {
		return new DefaultStreamValidationService(appRegistry,
				dockerValidatorProperties,
				streamDefinitionRepository,
				streamDefinitionService);
	}

	@Bean
	public TaskValidationService taskValidationService(AppRegistryService appRegistry,
			DockerValidatorProperties dockerValidatorProperties,
			TaskDefinitionRepository taskDefinitionRepository) {
		return new DefaultTaskValidationService(appRegistry,
				dockerValidatorProperties,
				taskDefinitionRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public StreamDefinitionService streamDefinitionService() {
		return new DefaultStreamDefinitionService();
	}

	@Bean
	public StreamService streamService(StreamDefinitionRepository streamDefinitionRepository,
			SkipperStreamDeployer skipperStreamDeployer,
			AppDeploymentRequestCreator appDeploymentRequestCreator,
			StreamValidationService streamValidationService,
			AuditRecordService auditRecordService,
			StreamDefinitionService streamDefinitionService) {
		return new DefaultStreamService(streamDefinitionRepository, skipperStreamDeployer,
				appDeploymentRequestCreator, streamValidationService, auditRecordService, streamDefinitionService);
	}

	@Bean
	public ContainerRegistryService containerRegistryService() {
		return mock(ContainerRegistryService.class);
	}

	@Bean
	public AppDeploymentRequestCreator streamDeploymentPropertiesUtils(AppRegistryService appRegistry,
			CommonApplicationProperties commonApplicationProperties,
			ApplicationConfigurationMetadataResolver applicationConfigurationMetadataResolver,
			StreamDefinitionService streamDefinitionService) {
		return new AppDeploymentRequestCreator(appRegistry,
				commonApplicationProperties,
				applicationConfigurationMetadataResolver,
				streamDefinitionService);
	}

	@Bean
	public SkipperStreamDeployer skipperStreamDeployer(SkipperClient skipperClient,
			AppRegistryService appRegistryService,
			StreamDefinitionRepository streamDefinitionRepository,
			StreamDefinitionService streamDefinitionService) {
		return new SkipperStreamDeployer(skipperClient, streamDefinitionRepository, appRegistryService,
				new ForkJoinPool(2), streamDefinitionService);
	}

	@Bean
	public SkipperClient skipperClient() {
		SkipperClient skipperClient = mock(SkipperClient.class);

		// Handle Skipper Info
		AboutResource aboutResource = new AboutResource();
		aboutResource.getVersionInfo().setServer(new Dependency());
		aboutResource.getVersionInfo().getServer().setName("skipper server");
		aboutResource.getVersionInfo().getServer().setVersion("1.0");
		when(skipperClient.info()).thenReturn(aboutResource);

		// Handle Skipper List Deployers
		List<Deployer> deployers = new ArrayList<>();
		// deployers.add(new Deployer("", "", null));
		when(skipperClient.listDeployers()).thenReturn(deployers);

		return skipperClient;
	}

	@Bean
	public DefaultStreamDefinitionAssemblerProvider streamDefinitionAssemblerProvider(
			StreamDefinitionService streamDefinitionService, StreamService streamService) {
		return new DefaultStreamDefinitionAssemblerProvider(streamDefinitionService, streamService);
	}

	@Bean
	public StreamDefinitionController streamDefinitionController(StreamService streamService,
			StreamDefinitionService streamDefinitionService, AppRegistryService appRegistryService,
			StreamDefinitionAssemblerProvider streamDefinitionAssemblerProvider,
			AppRegistrationAssemblerProvider appRegistrationAssemblerProvider) {
		return new StreamDefinitionController(streamService, streamDefinitionService, appRegistryService,
				streamDefinitionAssemblerProvider, appRegistrationAssemblerProvider);
	}

	@Bean
	public StreamValidationController streamValidationController(StreamService streamService) {
		return new StreamValidationController(streamService);
	}

	@Bean
	public AuditRecordController auditRecordController(AuditRecordService auditRecordService) {
		return new AuditRecordController(auditRecordService);
	}

	@Bean
	public MethodValidationPostProcessor methodValidationPostProcessor() {
		return new MethodValidationPostProcessor();
	}

	@Bean
	public CompletionController completionController(StreamCompletionProvider streamCompletionProvider,
			TaskCompletionProvider taskCompletionProvider) {
		return new CompletionController(streamCompletionProvider, taskCompletionProvider);
	}

	@Bean
	public ToolsController toolsController() {
		return new ToolsController();
	}

	@Bean
	public AppRegistryService appRegistryService(AppRegistrationRepository appRegistrationRepository,
			AppResourceCommon appResourceService, AuditRecordService auditRecordService) {
		return new DefaultAppRegistryService(appRegistrationRepository, appResourceService, auditRecordService);
	}

	@Bean
	public AppRegistryController appRegistryController(
			Optional<StreamDefinitionRepository> streamDefinitionRepository,
			Optional<StreamService> streamService,
			AppRegistryService appRegistry,
			ApplicationConfigurationMetadataResolver metadataResolver,
			StreamDefinitionService streamDefinitionService,
			AppRegistrationAssemblerProvider appRegistrationAssemblerProvider) {
		return new AppRegistryController(streamDefinitionRepository, streamService, appRegistry, metadataResolver,
				new ForkJoinPool(2), streamDefinitionService, appRegistrationAssemblerProvider);
	}

	@Bean
	public AppRegistrationAssemblerProvider appRegistryAssemblerProvider() {
		return new DefaultAppRegistrationAssemblerProvider();
	}

	@Bean
	public RuntimeAppsController runtimeAppsController(StreamDeployer streamDeployer) {
		return new RuntimeAppsController(streamDeployer);
	}

	@Bean
	public RuntimeStreamsController runtimeStreamsControllerV2(StreamDeployer streamDeployer) {
		return new RuntimeStreamsController(streamDeployer);
	}

	@Bean
	public RuntimeAppInstanceController appInstanceController(StreamDeployer streamDeployer) {
		return new RuntimeAppInstanceController(streamDeployer);
	}

	@Bean
	public TaskDefinitionAssemblerProvider taskDefinitionAssemblerProvider(TaskExecutionService taskExecutionService, TaskJobService taskJobService, TaskExplorer taskExplorer) {
		return new DefaultTaskDefinitionAssemblerProvider(taskExecutionService, taskJobService, taskExplorer);
	}

	@Bean
	public TaskDefinitionController taskDefinitionController(TaskExplorer explorer, TaskDefinitionRepository repository,
			TaskSaveService taskSaveService, TaskDeleteService taskDeleteService,
			TaskDefinitionAssemblerProvider taskDefinitionAssemblerProvider) {
		return new TaskDefinitionController(explorer, repository, taskSaveService, taskDeleteService,
				taskDefinitionAssemblerProvider);
	}

	@Bean
	public TaskExecutionController taskExecutionController(TaskExplorer explorer,
			ApplicationConfigurationMetadataResolver metadataResolver,
			AppRegistryService appRegistry, LauncherRepository launcherRepository,
			AuditRecordService auditRecordService,
			CommonApplicationProperties commonApplicationProperties, TaskValidationService taskValidationService,
			TaskDefinitionRepository taskDefinitionRepository, TaskExecutionService taskExecutionService,
			TaskExecutionInfoService taskExecutionInfoService, TaskDeleteService taskDeleteService,
			TaskJobService taskJobService) {
		return new TaskExecutionController(
				explorer, taskExecutionService,
				taskDefinitionRepository, taskExecutionInfoService,
				taskDeleteService, taskJobService);
	}

	@Bean
	public TasksInfoController taskExecutionsInfoController(TaskExecutionService taskExecutionService) {
		return new TasksInfoController(taskExecutionService);
	}

	@Bean
	public TaskPlatformController taskPlatformController(LauncherService launcherService) {
		return new TaskPlatformController(launcherService);
	}


	@Bean
	LauncherService launcherService(LauncherRepository launcherRepository) {
		return new DefaultLauncherService(launcherRepository);
	}

	@Bean
	public TaskSchedulerController taskSchedulerController(
			SchedulerService schedulerService) {
		return new TaskSchedulerController(schedulerService);
	}

	@Bean
	public TaskValidationController taskValidationController(TaskValidationService taskValidationService) {
		return new TaskValidationController(taskValidationService);
	}

	@Bean
	public TaskRepository taskRepository(DataSource dataSource) {
		return new SimpleTaskRepository(new TaskExecutionDaoFactoryBean(dataSource));
	}

	@Bean
	public DataflowTaskExecutionDao dataflowTaskExecutionDao(DataSource dataSource, TaskProperties taskProperties) {
		return new JdbcDataflowTaskExecutionDao(dataSource, taskProperties);
	}

	@Bean
	public DataflowJobExecutionDao dataflowJobExecutionDao(DataSource dataSource) {
		return new JdbcDataflowJobExecutionDao(dataSource, AbstractJdbcBatchMetadataDao.DEFAULT_TABLE_PREFIX);
	}

	@Bean
	public DataFlowAppRegistryPopulator dataflowAppRegistryServicePopulator(AppRegistryService appRegistry) {
		return new DataFlowAppRegistryPopulator(appRegistry, "classpath:META-INF/test-apps.properties");
	}

	@Bean
	public AppDeployer appDeployer() {
		return mock(AppDeployer.class);
	}

	@Bean
	public TaskLauncher taskLauncher() {
		return mock(TaskLauncher.class);
	}

	@Bean
	public Launcher launcher() {
		return mock(Launcher.class);
	}

	@Bean
	public TaskExplorer taskExplorer() {
		return mock(TaskExplorer.class);
	}

	@Bean
	public TaskJobService taskJobService() {
		return mock(TaskJobService.class);
	}

	@Bean
	public TaskDeleteService deleteTaskService(TaskExplorer taskExplorer, LauncherRepository launcherRepository,
			TaskDefinitionRepository taskDefinitionRepository,
			TaskDeploymentRepository taskDeploymentRepository,
			AuditRecordService auditRecordService,
			DataflowTaskExecutionDao dataflowTaskExecutionDao,
			DataflowJobExecutionDao dataflowJobExecutionDao,
			DataflowTaskExecutionMetadataDao dataflowTaskExecutionMetadataDao,
			SchedulerService schedulerService,
			TaskConfigurationProperties taskConfigurationProperties,
			DataSource dataSource) {
		return new DefaultTaskDeleteService(taskExplorer, launcherRepository, taskDefinitionRepository,
				taskDeploymentRepository,
				auditRecordService,
				dataflowTaskExecutionDao,
				dataflowJobExecutionDao,
				dataflowTaskExecutionMetadataDao,
				schedulerService,
				taskConfigurationProperties,
				dataSource);
	}

	@Bean
	public TaskSaveService saveTaskService(TaskDefinitionRepository taskDefinitionRepository,
			AuditRecordService auditRecordService, AppRegistryService registry) {
		return new DefaultTaskSaveService(taskDefinitionRepository, auditRecordService, registry);
	}

	@Bean
	public TaskExecutionCreationService taskExecutionRepositoryService(TaskRepository taskRepository) {
		return new DefaultTaskExecutionRepositoryService(taskRepository);
	}

	@Bean
	TaskAppDeploymentRequestCreator taskAppDeploymentRequestCreator(
			CommonApplicationProperties commonApplicationProperties,
			ApplicationConfigurationMetadataResolver metadataResolver) {
		return new TaskAppDeploymentRequestCreator(commonApplicationProperties,
				metadataResolver, null);
	}

	@Bean
	public DataflowTaskExecutionDao dataflowTaskExecutionDao(DataSource dataSource) {
		return new JdbcDataflowTaskExecutionDao(dataSource, new TaskProperties());
	}

	@Bean
	public TaskExecutionService taskService(LauncherRepository launcherRepository,
			AuditRecordService auditRecordService,
			TaskRepository taskRepository,
			TaskExecutionInfoService taskExecutionInfoService,
			TaskDeploymentRepository taskDeploymentRepository,
			TaskExecutionCreationService taskExecutionRepositoryService,
			TaskAppDeploymentRequestCreator taskAppDeploymentRequestCreator,
			TaskExplorer taskExplorer, DataflowTaskExecutionDao dataflowTaskExecutionDao,
			DataflowTaskExecutionMetadataDao dataflowTaskExecutionMetadataDao,
			OAuth2TokenUtilsService oauth2TokenUtilsService,
			TaskSaveService taskSaveService,
			TaskConfigurationProperties taskConfigurationProperties,
			ComposedTaskRunnerConfigurationProperties composedTaskRunnerConfigurationProperties) {

		return new DefaultTaskExecutionService(
				launcherRepository, auditRecordService, taskRepository,
				taskExecutionInfoService, taskDeploymentRepository,
				taskExecutionRepositoryService, taskAppDeploymentRequestCreator,
				taskExplorer, dataflowTaskExecutionDao, dataflowTaskExecutionMetadataDao,
				oauth2TokenUtilsService, taskSaveService, taskConfigurationProperties,
				composedTaskRunnerConfigurationProperties);
	}

	@Bean
	public DataflowTaskExecutionMetadataDao dataflowTaskExecutionMetadataDao(DataSource dataSource, ApplicationContext context) {
		DataFieldMaxValueIncrementerFactory incrementerFactory = new DefaultDataFieldMaxValueIncrementerFactory(dataSource);
		String databaseType;
		try {
			databaseType = DatabaseType.fromMetaData(dataSource).name();
		}
		catch (MetaDataAccessException e) {
			throw new IllegalStateException(e);
		}
		return new JdbcDataflowTaskExecutionMetadataDao(dataSource, incrementerFactory.getIncrementer(databaseType,
				"task_execution_metadata_seq"));
	}

	@Bean
	public TaskExecutionInfoService taskDefinitionRetriever(AppRegistryService registry,
			TaskExplorer taskExplorer, TaskDefinitionRepository taskDefinitionRepository,
			TaskConfigurationProperties taskConfigurationProperties, LauncherRepository launcherRepository,
			List<TaskPlatform> platforms, ComposedTaskRunnerConfigurationProperties composedTaskRunnerConfigurationProperties) {
		return new DefaultTaskExecutionInfoService(new DataSourceProperties(),
				registry, taskExplorer, taskDefinitionRepository,
				taskConfigurationProperties, launcherRepository, platforms, composedTaskRunnerConfigurationProperties);
	}

	@Bean
	Scheduler scheduler() {
		return new SimpleTestScheduler();
	}

	@Bean
	public SchedulerService schedulerService(CommonApplicationProperties commonApplicationProperties,
			TaskPlatform taskPlatform, TaskDefinitionRepository taskDefinitionRepository,
			AppRegistryService registry, ResourceLoader resourceLoader,
			ApplicationConfigurationMetadataResolver metaDataResolver, AuditRecordService auditRecordService,
			TaskConfigurationProperties taskConfigurationProperties, DataSourceProperties dataSourceProperties,
			ComposedTaskRunnerConfigurationProperties composedTaskRunnerConfigurationProperties) {
		return new DefaultSchedulerService(commonApplicationProperties,
				Collections.singletonList(taskPlatform), taskDefinitionRepository,
				registry, resourceLoader,
				taskConfigurationProperties, dataSourceProperties, null,
				metaDataResolver, new SchedulerServiceProperties(), auditRecordService,
				composedTaskRunnerConfigurationProperties);
	}

	@Bean
	public TaskPlatform taskPlatform(Scheduler scheduler) {
		Launcher launcher = new Launcher("default", "defaultType", Mockito.mock(TaskLauncher.class), scheduler);
		List<Launcher> launchers = new ArrayList<>();
		launchers.add(launcher);
		TaskPlatform taskPlatform = new TaskPlatform("testTaskPlatform", launchers);
		return taskPlatform;
	}

	@Bean
	public AboutController aboutController(VersionInfoProperties versionInfoProperties,
			FeaturesProperties featuresProperties, StreamDeployer streamDeployer,
			DataflowMetricsProperties monitoringDashboardInfoProperties) {

		Launcher launcher = mock(Launcher.class);
		TaskLauncher taskLauncher = mock(TaskLauncher.class);
		LauncherRepository launcherRepository = mock(LauncherRepository.class);

		RuntimeEnvironmentInfo taskDeployerEnvInfo = new RuntimeEnvironmentInfo.Builder()
				.implementationName("testTaskDepImplementationName")
				.implementationVersion("testTaskDepImplementationVersion")
				.platformType("testTaskDepPlatformType")
				.platformApiVersion("testTaskDepPlatformApiVersion")
				.platformClientVersion("testTaskDepPlatformClientVersion")
				.spiClass(Class.class)
				.platformHostVersion("testTaskDepPlatformHostVersion").build();

		when(taskLauncher.environmentInfo()).thenReturn(taskDeployerEnvInfo);
		when(launcher.getTaskLauncher()).thenReturn(taskLauncher);
		when(launcherRepository.findByName("default")).thenReturn(launcher);

		return new AboutController(streamDeployer, launcherRepository,
				featuresProperties, versionInfoProperties,
				mock(SecurityStateBean.class), monitoringDashboardInfoProperties);
	}

	@Bean
	public RootController rootController(EntityLinks entityLinks) {
		return new RootController(entityLinks);
	}

	@Bean
	public JobExecutionController jobExecutionController() {
		return mock(JobExecutionController.class);
	}

	@Bean
	public JobExecutionThinController jobExecutionThinController() {
		return mock(JobExecutionThinController.class);
	}

	@Bean
	public JobStepExecutionController jobStepExecutionController() {
		return mock(JobStepExecutionController.class);
	}

	@Bean
	public JobStepExecutionProgressController jobStepExecutionProgressController() {
		return mock(JobStepExecutionProgressController.class);
	}

	@Bean
	public JobInstanceController jobInstanceController() {
		return mock(JobInstanceController.class);
	}

	@Bean
	public OAuth2TokenUtilsService oauth2TokenUtilsService() {
		return mock(OAuth2TokenUtilsService.class);
	}

	@Bean
	PlatformTransactionManager springCloudTaskTransactionManager(DataSource dataSource) {
		return new DataSourceTransactionManager(dataSource);
	}

	@Bean
	@Primary
	public PlatformTransactionManager transactionManager(
			ObjectProvider<TransactionManagerCustomizers> transactionManagerCustomizers) {
		JpaTransactionManager transactionManager = new JpaTransactionManager();
		transactionManagerCustomizers.ifAvailable((customizers) -> customizers.customize(transactionManager));
		return transactionManager;
	}
}
