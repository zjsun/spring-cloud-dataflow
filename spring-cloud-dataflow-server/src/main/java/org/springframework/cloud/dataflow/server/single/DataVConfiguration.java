package org.springframework.cloud.dataflow.server.single;

import org.apache.commons.compress.utils.Sets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.common.security.support.SecurityStateBean;
import org.springframework.cloud.dataflow.core.TaskDefinition;
import org.springframework.cloud.dataflow.server.controller.UiController;
import org.springframework.cloud.dataflow.server.controller.support.TaskExecutionControllerDeleteAction;
import org.springframework.cloud.dataflow.server.repository.TaskDefinitionRepository;
import org.springframework.cloud.dataflow.server.service.TaskDeleteService;
import org.springframework.cloud.dataflow.server.service.TaskExecutionService;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * @author Alex.Sun
 * @created 2021-10-28 14:15
 */
@Configuration
@EnableWebSecurity
@EnableAsync
@EnableScheduling
public class DataVConfiguration extends WebSecurityConfigurerAdapter {
    private final Log logger = LogFactory.getLog(DataVConfiguration.class);
    static String[] PERMIT_ALL_PATHS = {
            "/management/health",
            "/management/info",
            "/authenticate",
            "/security/info",
            "/assets/**",
            "/static/**",
            "/dashboard/**",
            "/favicon.ico",
            "/login",
            "/logout",
            "/about",
            "/"
    };

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    TaskDefinitionRepository taskDefinitionRepository;
    @Autowired
    TaskExecutionService taskExecutionService;
    @Autowired
    TaskDeleteService taskDeleteService;
    @Value("${datav.task.execution.retention.count:10}")
    int taskExecutionRetentionCount = 10;

    public DataVConfiguration(SecurityStateBean securityStateBean) {
        securityStateBean.setAuthenticationEnabled(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(PERMIT_ALL_PATHS).permitAll()
                .anyRequest().authenticated()
                //
                .and()
                .formLogin()
                .loginPage(UiController.WEB_UI_INDEX_PAGE_ROUTE).loginProcessingUrl("/login")
                .defaultSuccessUrl(UiController.WEB_UI_INDEX_PAGE_ROUTE, true).failureUrl(UiController.WEB_UI_INDEX_PAGE_ROUTE)
                .permitAll()
                //
                .and().httpBasic().realmName("DataV Flow Server")
                //
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl(UiController.WEB_UI_INDEX_PAGE_ROUTE)
                .permitAll()
                //
                .and().rememberMe().userDetailsService(userDetailsService)
                //
                .and().csrf().disable();
    }

    @Transactional
    @Scheduled(timeUnit = TimeUnit.SECONDS, fixedDelay = 60, initialDelay = 10)
    public void autoCleanupTaskExecutions() {
        logger.info("开始清理任务执行记录，每任务最多保留最近 " + taskExecutionRetentionCount + " 条执行记录 ...");
        long start = System.currentTimeMillis();
        AtomicInteger cleanedTaskCount = new AtomicInteger(0);
        AtomicInteger cleanedExecutionCount = new AtomicInteger(0);
        Pageable taskRequest = PageRequest.ofSize(50).withSort(Sort.Direction.ASC, "taskName");
        while (true) {
            Page<TaskDefinition> taskPage = taskDefinitionRepository.findAll(taskRequest);
            taskPage.forEach(taskDefinition -> {
                Set<Long> toCleanIds = taskExecutionService.getAllTaskExecutionIds(false, taskDefinition.getTaskName())
                        .stream().sorted(Collections.reverseOrder()).skip(taskExecutionRetentionCount).collect(Collectors.toSet());
                if (!toCleanIds.isEmpty()) {
                    logger.info("清理任务[" + taskDefinition.getTaskName() + "]，执行记录：" + toCleanIds);
                    taskDeleteService.cleanupExecutions(
                            Sets.newHashSet(TaskExecutionControllerDeleteAction.CLEANUP, TaskExecutionControllerDeleteAction.REMOVE_DATA),
                            toCleanIds);
                    cleanedTaskCount.addAndGet(1);
                    cleanedExecutionCount.addAndGet(toCleanIds.size());
                }
            });

            if (taskPage.hasNext()) {
                taskRequest = taskPage.nextPageable();
            } else {
                break;
            }
        }
        long dura = System.currentTimeMillis() - start;
        logger.info("任务清理执行完成，耗时：" + (dura / 1000) + "s，共清理 " + cleanedTaskCount.get() + " 个任务 " + cleanedExecutionCount.get() + " 条执行记录。");
    }
}
