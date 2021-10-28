package org.springframework.cloud.dataflow.server.single;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.common.security.support.SecurityStateBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
            "/dashboard/logout-success-oauth.html",
            "/favicon.ico",
            "/login"
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
                .loginPage("/login")
                .permitAll()
                //
                .and()
                .logout()
                .permitAll()
                //
                .and().rememberMe().userDetailsService(userDetailsService)
                //
                .and().csrf().disable();
    }

    @Controller
    public static class LoginController {
        @GetMapping(value = "/login", produces = TEXT_HTML_VALUE)
        public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
            request.getRequestDispatcher("/login.html").forward(request, response);
        }
    }
}
