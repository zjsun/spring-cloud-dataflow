package org.springframework.cloud.dataflow.server.single;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.common.security.support.SecurityStateBean;
import org.springframework.cloud.dataflow.server.controller.UiController;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

/**
 * @author Alex.Sun
 * @created 2021-10-28 14:15
 */
@Configuration
@EnableWebSecurity
public class DataVConfiguration extends WebSecurityConfigurerAdapter {
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
            "/"
    };

    @Autowired
    UserDetailsService userDetailsService;

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
                .loginPage("/login").defaultSuccessUrl("/", true).failureUrl("/")
                .permitAll()
                //
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("/")
                .permitAll()
                //
                .and().rememberMe().userDetailsService(userDetailsService)
                //
                .and().csrf().disable();
    }

    @Controller
    public static class DataVController {

        @Autowired
        UiController uiController;

        @RequestMapping(value = {"", "/"})
        public void index(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            uiController.index(request, response);
        }

        @GetMapping(value = "/login", produces = TEXT_HTML_VALUE)
        public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
            request.getRequestDispatcher("/login.html").forward(request, response);
        }
    }
}
