package com.example.SpringSecurityEx.config;

import com.example.SpringSecurityEx.jwt.AuthEntryPointJwt;
import com.example.SpringSecurityEx.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    // ** Custom Filer Chain
    @Bean
    SecurityFilterChain defaultSecurityFilterChain (HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(requests -> requests.requestMatchers("/h2-console/**").permitAll()
//                .anyRequest().authenticated());
//        //Used for creation stateless API, cookies won't be available in this
//        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
////        http.formLogin(Customizer.withDefaults());
//        http.httpBasic(Customizer.withDefaults());
//        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
//        http.csrf(AbstractHttpConfigurer::disable);
//        return http.build();


        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated());
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.httpBasic(withDefaults());
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                )
        );
        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("pass"))
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    //.password(passwordEncoder().encode("adminPass"))
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    // **In Memory Authentication
//    @Bean
//    public UserDetailsService userDetailsService(){
//
//        UserDetails user1 = User.withUsername("user1")
////                .password("{noop}pass")
//                .password(passwordEncoder().encode("pass"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
////                .password("{noop}adminPass")  noop is used to tell that no encoding is done, used before using PasswordEncoder
//                .password(passwordEncoder().encode("adminPass"))
//                .roles("ADMIN")
//                .build();
//
////        return new InMemoryUserDetailsManager(user1, admin);
//
//
//        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//
//        return userDetailsManager;
//
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
