/*
 * Copyright 2015-2019 the original author or authors.
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

package org.springframework.cloud.dataflow.server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.dataflow.rest.Version;
import org.springframework.cloud.dataflow.rest.resource.*;
import org.springframework.cloud.dataflow.rest.resource.about.AboutResource;
import org.springframework.cloud.dataflow.server.config.features.FeaturesProperties;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.EntityLinks;
import org.springframework.hateoas.server.ExposesResourceFor;
import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for the root resource of the Data Flow server.
 *
 * @author Patrick Peralta
 * @author Ilayaperumal Gopinathan
 * @author Glenn Renfro
 * @author Mark Fisher
 * @author Gunnar Hillert
 */
@RestController
@EnableConfigurationProperties(FeaturesProperties.class)
@ExposesResourceFor(RootResource.class)
public class RootController {

    /**
     * Contains links pointing to controllers backing an entity type (such as streams).
     */
    private final EntityLinks entityLinks;

    @Autowired
    private FeaturesProperties featuresProperties;

    /**
     * Construct an {@code RootController}.
     *
     * @param entityLinks holder of links to controllers and their associated entity types
     */
    public RootController(EntityLinks entityLinks) {
        this.entityLinks = entityLinks;
    }

    /**
     * Return a {@link RepresentationModel} object containing the resources served by the Data
     * Flow server.
     *
     * @return {@code RepresentationModel} object containing the Data Flow server's resources
     */
//	@RequestMapping("/")
    public RootResource info() {
        RootResource root = new RootResource(Version.REVISION);

        root.add(WebMvcLinkBuilder.linkTo(UiController.class).withRel("dashboard"));
        root.add(WebMvcLinkBuilder.linkTo(AuditRecordController.class).withRel("audit-records"));

        if (featuresProperties.isStreamsEnabled()) {
            root.add(entityLinks.linkToCollectionResource(StreamDefinitionResource.class)
                    .withRel("streams/definitions"));
            root.add(
                    unescapeTemplateVariables(entityLinks.linkToItemResource(StreamDefinitionResource.class, "{name}")
                            .withRel("streams/definitions/definition")));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(StreamAppStatusResource.class, "{name}")
                    .withRel("streams/validation")));

            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeStreamsController.class).status(null, null, null)).withRel("runtime/streams"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeStreamsController.class).streamStatus(null, null, null)).withRel("runtime/streams/{streamNames}"));

            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeAppsController.class).list(null, null)).withRel("runtime/apps"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeAppsController.class).display(null)).withRel("runtime/apps/{appId}"));

            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeAppInstanceController.class).list(null, null, null)).withRel("runtime/apps/{appId}/instances"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(RuntimeAppInstanceController.class).display(null, null)).withRel("runtime/apps/{appId}/instances/{instanceId}"));

            root.add(WebMvcLinkBuilder.linkTo(StreamDeploymentController.class).withRel("streams/deployments"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).info(null, false)).withRel("streams/deployments/{name}{?reuse-deployment-properties}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).deploy(null, null)).withRel("streams/deployments/{name}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).history(null)).withRel("streams/deployments/history/{name}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).manifest(null, null)).withRel("streams/deployments/manifest/{name}/{version}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).platformList()).withRel("streams/deployments/platform/list"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).rollback(null, null)).withRel("streams/deployments/rollback/{name}/{version}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).update(null, null)).withRel("streams/deployments/update/{name}"));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(StreamDeploymentResource.class, "{name}").withRel("streams/deployments/deployment")));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamDeploymentController.class).scaleApplicationInstances(null, null, null, null)).withRel("streams/deployments/scale/{streamName}/{appName}/instances/{count}"));
            root.add(WebMvcLinkBuilder.linkTo(StreamLogsController.class).withRel("streams/logs"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamLogsController.class).getLog(null)).withRel("streams/logs/{streamName}"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(StreamLogsController.class).getLog(null, null)).withRel("streams/logs/{streamName}/{appName}"));
        }
        if (featuresProperties.isTasksEnabled()) {
            root.add(entityLinks.linkToCollectionResource(LauncherResource.class).withRel("tasks/platforms"));

            root.add(entityLinks.linkToCollectionResource(TaskDefinitionResource.class).withRel("tasks/definitions"));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(TaskDefinitionResource.class, "{name}")
                    .withRel("tasks/definitions/definition")));
            root.add(entityLinks.linkToCollectionResource(TaskExecutionResource.class).withRel("tasks/executions"));
            String taskTemplated = entityLinks.linkToCollectionResource(TaskExecutionResource.class).getHref()
                    + "{?name}";
            root.add(Link.of(taskTemplated).withRel("tasks/executions/name"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(TaskExecutionController.class)
                    .getCurrentTaskExecutionsInfo()).withRel("tasks/executions/current"));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(TaskExecutionResource.class, "{id}")
                    .withRel("tasks/executions/execution")));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(TaskAppStatusResource.class, "{name}")
                    .withRel("tasks/validation")));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(TasksInfoController.class).getInfo(null, null)).withRel("tasks/info/executions"));
            root.add(WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(TaskLogsController.class).getLog(null, null)).withRel("tasks/logs"));

            if (featuresProperties.isSchedulesEnabled()) {
                root.add(entityLinks.linkToCollectionResource(ScheduleInfoResource.class).withRel("tasks/schedules"));
                String scheduleTemplated = entityLinks.linkToCollectionResource(ScheduleInfoResource.class).getHref()
                        + "/instances/{taskDefinitionName}";
                root.add(Link.of(scheduleTemplated).withRel("tasks/schedules/instances"));
            }
            root.add(entityLinks.linkToCollectionResource(JobExecutionResource.class).withRel("jobs/executions"));
            taskTemplated = entityLinks.linkToCollectionResource(JobExecutionResource.class).getHref() + "{?name}";
            root.add(Link.of(taskTemplated).withRel("jobs/executions/name"));
            taskTemplated = entityLinks.linkToCollectionResource(JobExecutionResource.class).getHref() + "{?status}";
            root.add(Link.of(taskTemplated).withRel("jobs/executions/status"));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(JobExecutionResource.class, "{id}")
                    .withRel("jobs/executions/execution")));
            root.add(unescapeTemplateVariables(entityLinks.linkFor(StepExecutionResource.class, "{jobExecutionId}")
                    .withRel("jobs/executions/execution/steps")));
            root.add(unescapeTemplateVariables(entityLinks.linkFor(StepExecutionResource.class, "{jobExecutionId}")
                    .slash("{stepId}").withRel("jobs/executions/execution/steps/step")));
            root.add(unescapeTemplateVariables(
                    entityLinks.linkFor(StepExecutionProgressInfoResource.class, "{jobExecutionId}").slash("{stepId}")
                            .slash("progress").withRel("jobs/executions/execution/steps/step/progress")));
            taskTemplated = entityLinks.linkToCollectionResource(JobInstanceResource.class).getHref() + "{?name}";
            root.add(Link.of(taskTemplated).withRel("jobs/instances/name"));
            root.add(unescapeTemplateVariables(entityLinks.linkToItemResource(JobInstanceResource.class, "{id}")
                    .withRel("jobs/instances/instance")));
            root.add(entityLinks.linkFor(TaskToolsResource.class).withRel("tools/parseTaskTextToGraph"));
            root.add(entityLinks.linkFor(TaskToolsResource.class).withRel("tools/convertTaskGraphToText"));
            root.add(entityLinks.linkToCollectionResource(JobExecutionThinResource.class).withRel("jobs/thinexecutions"));
            taskTemplated = entityLinks.linkToCollectionResource(JobExecutionThinResource.class).getHref() + "{?name}";
            root.add(Link.of(taskTemplated).withRel("jobs/thinexecutions/name"));
            taskTemplated = entityLinks.linkToCollectionResource(JobExecutionThinResource.class).getHref() + "{?jobInstanceId}";
            root.add(Link.of(taskTemplated).withRel("jobs/thinexecutions/jobInstanceId"));
            taskTemplated = entityLinks.linkToCollectionResource(JobExecutionThinResource.class).getHref() + "{?taskExecutionId}";
            root.add(Link.of(taskTemplated).withRel("jobs/thinexecutions/taskExecutionId"));

        }
        root.add(entityLinks.linkToCollectionResource(AppRegistrationResource.class).withRel("apps"));
        root.add(entityLinks.linkToCollectionResource(AboutResource.class).withRel("about"));

        String completionStreamTemplated = entityLinks.linkFor(CompletionProposalsResource.class).withSelfRel()
                .getHref() + ("/stream{?start,detailLevel}");
        root.add(Link.of(completionStreamTemplated).withRel("completions/stream"));
        String completionTaskTemplated = entityLinks.linkFor(CompletionProposalsResource.class).withSelfRel().getHref()
                + ("/task{?start,detailLevel}");
        root.add(Link.of(completionTaskTemplated).withRel("completions/task"));

        return root;
    }

    // Workaround https://github.com/spring-projects/spring-hateoas/issues/234
    private Link unescapeTemplateVariables(Link raw) {
        return Link.of(raw.getHref().replace("%7B", "{").replace("%7D", "}"), raw.getRel());
    }

}
