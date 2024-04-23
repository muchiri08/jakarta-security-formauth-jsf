package com.muchiri.jakarta.security.form.login.web.controller;

import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.security.enterprise.SecurityContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 * @author muchiri
 */
@Named("home")
@RequestScoped
public class HomeController {

    private String loggedInUser;

    @Inject
    private FacesContext facesContext;
    @Inject
    private SecurityContext securityContext;

    public String getLoggedInUser() {
        return securityContext.getCallerPrincipal().getName();
    }

    public String logout() throws ServletException {
        ExternalContext ctx = facesContext.getExternalContext();
        ((HttpServletRequest) ctx.getRequest()).logout();
        return "/login?faces-redirect=true";
    }
}
