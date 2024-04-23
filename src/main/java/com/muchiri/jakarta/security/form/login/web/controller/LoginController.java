package com.muchiri.jakarta.security.form.login.web.controller;

import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import java.io.IOException;

/**
 *
 * @author muchiri
 */
@Named("login")
@RequestScoped
public class LoginController {

    @NotBlank(message = "username required")
    private String username;
    @NotBlank(message = "password required")
    private String password;

    @Inject
    private Pbkdf2PasswordHash passwordHash;
    @Inject
    private FacesContext facesContext;
    @Inject
    private SecurityContext securityContext;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void execute() {
        System.out.println("login process started");
        switch (processAuthentication()) {
            case SEND_CONTINUE:
                System.out.println("send continue");
                facesContext.responseComplete();
                break;
            case SEND_FAILURE:
                System.out.println("send failure");
                facesContext.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "invalid credentials", null));
                break;
            case SUCCESS:
                System.out.println("success");
                try {
                    String home = getExternalContext().getRequestContextPath() + "/app/home";
                    getExternalContext().redirect(home);
                } catch (IOException ex) {
                    System.err.format("error during log in. error message => %s", ex.getMessage());
                    //we can redirect to server error page to notify the user
                }
                break;
        }
    }

    private AuthenticationStatus processAuthentication() {
        ExternalContext ctx = getExternalContext();
        return securityContext.authenticate(
                (HttpServletRequest) ctx.getRequest(),
                (HttpServletResponse) ctx.getResponse(),
                AuthenticationParameters.withParams().credential(new UsernamePasswordCredential(username, password)));
    }

    private ExternalContext getExternalContext() {
        return facesContext.getExternalContext();
    }

}
