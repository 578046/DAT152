package no.hvl.dat152.obl4.util;

import java.security.SecureRandom;


import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.codec.binary.Base64;

public class Validator {

	public static String validString(String parameter) {
		return parameter != null ? parameter : "null";
	}
	
	public static boolean validPassword(String password){
		return password.length() >= 8;
	}
	
	public static boolean validCSRFToken(HttpServletRequest request) {
		String requestToken = request.getParameter("csrftoken");
			
		String sessionToken = (String) request.getSession().getAttribute("csrftoken");
			
		return requestToken.equals(sessionToken);
	}
		
	public static String generateCSRFToken(HttpServletRequest request) {
		SecureRandom sr = new SecureRandom();
		byte[] csrf = new byte[16];
		sr.nextBytes(csrf);
		String token = Base64.encodeBase64URLSafeString(csrf);
		request.getSession().setAttribute("csrftoken", token);
		return token;
	}

}
