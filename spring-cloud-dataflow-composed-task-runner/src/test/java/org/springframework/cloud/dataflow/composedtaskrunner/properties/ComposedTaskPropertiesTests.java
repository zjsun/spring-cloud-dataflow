/*
 * Copyright 2017-2021 the original author or authors.
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

package org.springframework.cloud.dataflow.composedtaskrunner.properties;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.dataflow.core.Base64Utils;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Glenn Renfro
 * @author Gunnar Hillert
 */
public class ComposedTaskPropertiesTests {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

	@Test
	public void testGettersAndSetters() throws URISyntaxException{
		ComposedTaskProperties properties = new ComposedTaskProperties();
		properties.setComposedTaskProperties("aaa");
		properties.setComposedTaskArguments("bbb");
		properties.setIntervalTimeBetweenChecks(12345);
		properties.setMaxWaitTime(6789);
		properties.setDataflowServerUri(new URI("http://test"));
		properties.setGraph("ddd");
		properties.setDataflowServerUsername("foo");
		properties.setDataflowServerPassword("bar");
		properties.setDataflowServerAccessToken("foobar");
		properties.setSkipTlsCertificateVerification(true);
		assertThat(properties.getComposedTaskProperties()).isEqualTo("aaa");
		assertThat(properties.getComposedTaskArguments()).isEqualTo("bbb");
		assertThat(properties.getIntervalTimeBetweenChecks()).isEqualTo(12345);
		assertThat(properties.getMaxWaitTime()).isEqualTo(6789);
		assertThat(properties.getDataflowServerUri().toString()).isEqualTo("http://test");
		assertThat(properties.getGraph()).isEqualTo("ddd");
		assertThat(properties.getDataflowServerUsername()).isEqualTo("foo");
		assertThat(properties.getDataflowServerPassword()).isEqualTo("bar");
		assertThat(properties.getDataflowServerAccessToken()).isEqualTo("foobar");
		assertThat(properties.isSkipTlsCertificateVerification()).isTrue();
		assertThat(properties.isIncrementInstanceEnabled()).isTrue();
		assertThat(properties.isUuidInstanceEnabled()).isFalse();
		properties.setUuidInstanceEnabled(true);
		properties.setIncrementInstanceEnabled(false);
		assertThat(properties.isIncrementInstanceEnabled()).isFalse();
		assertThat(properties.isUuidInstanceEnabled()).isTrue();
	}

	@Test
	public void testDataflowServerURIDefaults() {
		ComposedTaskProperties properties = new ComposedTaskProperties();
		assertThat(properties.getDataflowServerUri().toString()).isEqualTo("http://localhost:9393");
	}

	@Test
	public void testSkipSslVerificationDefaults() {
		ComposedTaskProperties properties = new ComposedTaskProperties();
		assertThat(properties.isSkipTlsCertificateVerification()).isFalse();
	}

	@Test
	public void testThreadDefaults() {
		ComposedTaskProperties properties = new ComposedTaskProperties();
		assertThat(properties.getSplitThreadCorePoolSize()).isEqualTo(ComposedTaskProperties.SPLIT_THREAD_CORE_POOL_SIZE_DEFAULT);
		assertThat(properties.getSplitThreadKeepAliveSeconds()).isEqualTo(ComposedTaskProperties.SPLIT_THREAD_KEEP_ALIVE_SECONDS_DEFAULT);
		assertThat(properties.getSplitThreadMaxPoolSize()).isEqualTo(ComposedTaskProperties.SPLIT_THREAD_MAX_POOL_SIZE_DEFAULT);
		assertThat(properties.getSplitThreadQueueCapacity()).isEqualTo(ComposedTaskProperties.SPLIT_THREAD_QUEUE_CAPACITY_DEFAULT);
		assertThat(properties.getDataflowServerUri().toString()).isEqualTo("http://localhost:9393");
		assertThat(properties.isSplitThreadAllowCoreThreadTimeout()).isFalse();
		assertThat(properties.isSplitThreadWaitForTasksToCompleteOnShutdown()).isFalse();
		assertThat(properties.getDataflowServerUsername()).isNull();
		assertThat(properties.getDataflowServerPassword()).isNull();
	}

	@Test
	public void testComposedTaskAppArguments() {
		this.contextRunner
				.withInitializer(context -> {
					Map<String, Object> map = new HashMap<>();
					map.put("composed-task-app-arguments.app.AAA", "arg1");
					map.put("composed-task-app-arguments.app.AAA.1", "arg2");
					map.put("composed-task-app-arguments.app.AAA.2", "arg3");
					map.put("composed-task-app-arguments." + Base64Utils.encode("app.*.3"), Base64Utils.encode("arg4"));
					map.put("composed-task-app-arguments." + Base64Utils.encode("app.*.4"), "arg5");
					context.getEnvironment().getPropertySources().addLast(new SystemEnvironmentPropertySource(
						StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, map));
				})
				.withUserConfiguration(Config1.class)
				.run((context) -> {
					ComposedTaskProperties properties = context.getBean(ComposedTaskProperties.class);
					assertThat(properties.getComposedTaskAppArguments()).hasSize(5);
					assertThat(properties.getComposedTaskAppArguments()).containsEntry("app.AAA", "arg1");
					assertThat(properties.getComposedTaskAppArguments()).containsEntry("app.AAA.1", "arg2");
					assertThat(properties.getComposedTaskAppArguments()).containsEntry("app.AAA.2", "arg3");
					assertThat(Base64Utils.decodeMap(properties.getComposedTaskAppArguments())).containsEntry("app.*.3", "arg4");
					assertThat(Base64Utils.decodeMap(properties.getComposedTaskAppArguments())).containsEntry("app.*.4", "arg5");
				});
	}

	@EnableConfigurationProperties({ ComposedTaskProperties.class })
	private static class Config1 {
	}
}
