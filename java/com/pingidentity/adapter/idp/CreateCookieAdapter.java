/*
 * **************************************************
 *  Copyright (C) 2017 Ping Identity Corporation
 *  All rights reserved.
 *
 *  The contents of this file are subject to the terms of the
 *  Ping Identity Corporation SDK Developer Guide.
 *
 *  Ping Identity Corporation
 *  1001 17th St Suite 100
 *  Denver, CO 80202
 *  303.468.2900
 *  http://www.pingidentity.com
 * ****************************************************
 */

package com.pingidentity.sample.adapter.idp;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.state.SessionStateSupport;

import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import com.pingidentity.sdk.template.TemplateRendererUtilException;

/**
 *
 * This class is an example of an IdP adapter that demonstrates the use of the Velocity Template Render {@link TemplateRendererUtil}
 *
 * This adapter is meant to be mapped in an SP connection that when invoked will present end users with a form prompting
 * input for a 'username' that can then be used later in a policy flow.
 *
 * This class does not handle any session state support, adapter chaining or input validation.
 *
 */
public class CreateCookieAdapter implements IdpAuthenticationAdapterV2 {

    private static final Logger log = LogManager.getLogger(CreateCookieAdapter.class);

    private static final String ADAPTER_NAME = "Create Cookie";
    private static final String USERNAME = "username";
    private static final String FORM_COOKIE_NAME_FIELD = "Cookie Name";
    private static final String FORM_COOKIE_DOMAIN_FIELD = "Cookie Domain";
    private static final String FORM_COOKIE_PATH_FIELD = "Cookie Path";

	private SessionStateSupport sessionState = new SessionStateSupport();
	
    /**
     * This is used to pass in session state between this adapter and the PromptForPassword adapter 
     * what source the user came from.
     * 
     * In this example it is only used t show how to pass values in session state between two adapters.
     * The value it self in this example is for demo and not actually used in the following adapter.
     * 
     */
    public static final String USER_LOCATION_SOURCE_ATTRIBUTE = "User_Location_Source";


    // Fields
    private IdpAuthnAdapterDescriptor descriptor = null;
    private Configuration configuration = null;


    /**
     * Constructor for the Create Cookie adapter. Initializes the adapter descriptor so PingFederate can
     * generate the proper configuration GUI
     */

    public CreateCookieAdapter() {
    	log.debug("Entering constructor: CreateCookieAdapter");
        // Create input text field to represent name of velocity html template file

        TextFieldDescriptor formCookieName = new TextFieldDescriptor(FORM_COOKIE_NAME_FIELD, "Name of your HTTP Cookie.  For example, SomeCookie.  Required.");
        formCookieName.setDefaultValue("SomeCookie");
        formCookieName.addValidator(new RequiredFieldValidator());

        TextFieldDescriptor formCookieDomain = new TextFieldDescriptor(FORM_COOKIE_DOMAIN_FIELD, "Cookie domain.  For example, example.com");
        formCookieDomain.setDefaultValue("localhost");
        formCookieDomain.addValidator(new RequiredFieldValidator());

        TextFieldDescriptor formCookiePath = new TextFieldDescriptor(FORM_COOKIE_PATH_FIELD, "Name of your HTTP Cookie.  For example, /something/");
        formCookiePath.setDefaultValue("/");
        formCookiePath.addValidator(new RequiredFieldValidator());

        // Create an adapter GUI descriptor
        AdapterConfigurationGuiDescriptor configurationGuiDescriptor = new AdapterConfigurationGuiDescriptor(ADAPTER_NAME);
        configurationGuiDescriptor.addField(formCookieName);
        configurationGuiDescriptor.addField(formCookieDomain);
        configurationGuiDescriptor.addField(formCookiePath);

        // Create an Idp adapter descriptor
        Set<String> attributeContract = new HashSet<String>();
        attributeContract.add(USERNAME);
        this.descriptor = new IdpAuthnAdapterDescriptor(this, ADAPTER_NAME, attributeContract, true, configurationGuiDescriptor, false);
    	log.debug("Leaving constructor: CreateCookieAdapter");
    }

    /**
     * This method is called by the PingFederate server to push configuration values entered by the administrator via
     * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
     * should use the {@link Configuration} parameter to configure its own internal state as needed. The tables and
     * fields available in the Configuration object will correspond to the tables and fields defined on the
     * {@link org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor} on the AuthnAdapterDescriptor returned
     * by the {@link #getAdapterDescriptor()} method of this class. <br/>
     * <br/>
     * Each time the PingFederate server creates a new instance of your adapter implementation this method will be
     * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
     * worry about them here. The server doesn't allow access to your adapter implementation instance until after
     * creation and configuration is completed.
     *
     * @param configuration
     *            the Configuration object constructed from the values entered by the user via the GUI.
     */

    @Override
    public void configure(Configuration config) {
    	log.debug("Entering method: configure");
        this.configuration = config;
    	log.debug("Leaving method: configure");

    }

    /**
     * The PingFederate server will invoke this method on your adapter implementation to discover metadata about the
     * implementation. This included the adapter's attribute contract and a description of what configuration fields to
     * render in the GUI. <br/>
     * <br/>
     *
     * @return an IdpAuthnAdapterDescriptor object that describes this IdP adapter implementation.
     */

    @Override
    public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
    	log.debug("Entering/Leaving method: getAdapterDescriptor");
        return this.descriptor;
    }

     /**
     * This is an extended method that the PingFederate server will invoke during processing of a single sign-on
     * transaction to lookup information about an authenticated security context or session for a user at the external
     * application or authentication provider service.
     * <p>
     * In this example, the adapter simply returns the username entered by user as part of its adapter contract. It
     * renders a template to request use input.
     * </p>
     *
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to. Accessing the HttpSession
     *            from the request is not recommended and doing so is deprecated. Use
     *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an alternative.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param inParameters
     *            A map that contains a set of input parameters. The input parameters provided are detailed in
     *            {@link IdpAuthenticationAdapterV2}, prefixed with <code>IN_PARAMETER_NAME_*</code> i.e.
     *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}.
     * @return {@link AuthnAdapterResponse} The return value should not be null.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse).
     */

    @Override
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters) throws AuthnAdapterException, IOException {
        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();

        log.debug("Entering method: lookupAuthN");

        // Handle Submit if clicked
        Map<String, Object> attributeMap = new HashMap<String, Object>();
        attributeMap.put(USERNAME, "michael@example.com");
       
        log.debug("debug: " + configuration.getFieldValue(FORM_COOKIE_NAME_FIELD));

        // lets create the cookie

        Cookie cookie = new Cookie(configuration.getFieldValue(FORM_COOKIE_NAME_FIELD), "myCookieValue");

        cookie.setDomain(configuration.getFieldValue(FORM_COOKIE_DOMAIN_FIELD));
        cookie.setPath(configuration.getFieldValue(FORM_COOKIE_PATH_FIELD));
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        
        resp.addCookie(cookie);

        // tell pingfederate that this adapter was a roaring success

        authnAdapterResponse.setAttributeMap(attributeMap);
        authnAdapterResponse.setUsername(req.getParameter(USERNAME));
        authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
        
        /*
            * Passing value in state to next adapter 
            */

        String userSourceValue = "some source value for HARDCODED";
        log.debug("what is being placed in " + USER_LOCATION_SOURCE_ATTRIBUTE + " is " + userSourceValue);
        sessionState.setAttribute(USER_LOCATION_SOURCE_ATTRIBUTE,  userSourceValue, req, resp, true);

        log.debug("Leaving method: lookupAuthN");
        return authnAdapterResponse;
    }

    /**
     *
     * This is a helper method that renders the template form via {@link TemplateRendererUtil} class.
     *
     *@param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to. Accessing the HttpSession
     *            from the request is not recommended and doing so is deprecated. Use
     *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an alternative.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param inParameters
     *            A map that contains a set of input parameters. The input parameters provided are detailed in
     *            {@link IdpAuthenticationAdapterV2}, prefixed with <code>IN_PARAMETER_NAME_*</code> i.e.
     *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     */

    private void renderForm(HttpServletRequest req, HttpServletResponse resp,  Map<String, Object> inParameters) throws AuthnAdapterException {
        log.debug("Entering method: renderForm");

    	Map<String, Object> params = new HashMap<String, Object>();
        params.put("resumePath", inParameters.get(IN_PARAMETER_NAME_RESUME_PATH));
        params.put("username", USERNAME);

        try {
            TemplateRendererUtil.render(req, resp, configuration.getFieldValue(FORM_COOKIE_NAME_FIELD), params);
        } catch (TemplateRendererUtilException e) {
            throw new AuthnAdapterException(e);
        }
        log.debug("Leaving method: renderForm");
    }

    /**
     * This is the method that the PingFederate server will invoke during processing of a single logout to terminate a
     * security context for a user at the external application or authentication provider service.
     *
     * <p>
     * In this example, no extra action is needed to logout so simply return true.
     * </p>
     *
     * @param authnIdentifiers
     *            the map of authentication identifiers originally returned to the PingFederate server by the
     *            {@link #lookupAuthN} method. This enables the adapter to associate a security context or session
     *            returned by lookupAuthN with the invocation of this logout method.
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param resumePath
     *            the relative URL that the user agent needs to return to, if the implementation of this method
     *            invocation needs to operate asynchronously. If this method operates synchronously, this parameter can
     *            be ignored. The resumePath is the full path portion of the URL - everything after hostname and port.
     *            If the hostname, port, or protocol are needed, they can be derived using the HttpServletRequest.
     * @return a boolean indicating if the logout was successful.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse will throw
     *             an IOException.
     *
     * @see IdpAuthenticationAdapter#logoutAuthN(Map, HttpServletRequest, HttpServletResponse, String)
     */
    @Override
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath) throws AuthnAdapterException, IOException {
    	log.debug("Entering/Leaving method: logoutAuthN");
    	return true;
    }

    /**
     * This method is used to retrieve information about the adapter (e.g. AuthnContext).
     * <p>
	 * This method will allow PingFederate to retrieve information about the adapter (for example, AuthnContext). 
	 * NOTE: The feature is intended for future releases of PingFederate and is not currently supported. It can safely return null.     
	 * </p>
     *
     * @return a map
     */
    @Override
    public Map<String, Object> getAdapterInfo() {
    	log.debug("Entering/Leaving method: getAdapterInfo");
        return null;
    }

    /**
     * This method is deprecated. It is not called when IdpAuthenticationAdapterV2 is implemented. It is replaced by
     * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
     *
     */
    @Override
    @Deprecated
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath) throws AuthnAdapterException, IOException {

    	log.debug("Entering/Leaving method: lookupAuthN deprecated");
    	throw new UnsupportedOperationException();

    }
}
