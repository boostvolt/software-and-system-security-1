package ch.zhaw.securitylab.marketplace.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final LoginThrottlingFilter loginThrottlingFilter;
    private final CustomAuthFailureHandler authFailureHandler;
    private final CustomAuthSuccessHandler authSuccessHandler;
    private final BlockLoginPostRequestFilter blockLoginPostRequestFilter;

    public SecurityConfig(LoginThrottlingFilter loginThrottlingFilter,
                          CustomAuthFailureHandler authFailureHandler,
                          CustomAuthSuccessHandler authSuccessHandler,
                          BlockLoginPostRequestFilter blockLoginPostRequestFilter) {
        this.loginThrottlingFilter = loginThrottlingFilter;
        this.authFailureHandler = authFailureHandler;
        this.authSuccessHandler = authSuccessHandler;
        this.blockLoginPostRequestFilter = blockLoginPostRequestFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                    .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                    .requestMatchers("/", "/public/**", "/css/*").permitAll()
                    .requestMatchers("/admin/deletepurchase/*").hasRole("SALES")
                    .requestMatchers("/admin/deleteproduct/*").hasRole("PRODUCTMANAGER")
                    .requestMatchers("/admin/addproduct").hasRole("PRODUCTMANAGER")
                    .requestMatchers("/admin/saveproduct").hasRole("PRODUCTMANAGER")
                    .requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES", "PRODUCTMANAGER", "BURGERMAN")
                    .anyRequest().denyAll()
                )
                .formLogin(formLoginConfigurer -> formLoginConfigurer
                    .loginPage("/public/login")
                    .failureHandler(authFailureHandler)
                    .successHandler(authSuccessHandler)
                    .permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/public/products?logout=true"))
                .requiresChannel(channel -> channel.anyRequest().requiresSecure())
                .addFilterBefore(blockLoginPostRequestFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(loginThrottlingFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}