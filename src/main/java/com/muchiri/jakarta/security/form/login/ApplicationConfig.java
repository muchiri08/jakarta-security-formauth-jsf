package com.muchiri.jakarta.security.form.login;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.faces.annotation.FacesConfig;
import jakarta.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;
import jakarta.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;

/**
 *
 * @author muchiri
 */
@DatabaseIdentityStoreDefinition(
        callerQuery = "select password from basic_auth_user where username = ?",
        groupsQuery = "select name from basic_auth_group where username = ?",
        dataSourceLookup = "jdbc/kennedy_resource"
)
@CustomFormAuthenticationMechanismDefinition(
        loginToContinue = @LoginToContinue(
                loginPage = "/login",
                errorPage = "",
                useForwardToLogin = false
        )
)
@FacesConfig
@ApplicationScoped
public class ApplicationConfig {
}
