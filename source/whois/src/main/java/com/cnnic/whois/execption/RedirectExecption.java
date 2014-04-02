package com.cnnic.whois.execption;
/**
 * redirect exception
 * @author nic
 *
 */
public class RedirectExecption extends Exception {
	private String redirectURL;

	/**
	 * constructed a object
	 */
	public RedirectExecption() {
	}

	/**
	 * Use redirectURL constructed a new object
	 * 
	 * @param redirectURL
	 */
	public RedirectExecption(String redirectURL) {
		this.redirectURL = redirectURL;
	}

	/**
	 * Use msg constructed a new object
	 * 
	 * @param msg
	 */
	public RedirectExecption(Exception msg) {
		super(msg);
	}

	/**
	 * Get redirectURL
	 * 
	 * @return redirectURL
	 */
	public String getRedirectURL() {
		return redirectURL;
	}

	/**
	 * Set redirectURL
	 * 
	 * @param redirectURL
	 */
	public void setRedirectURL(String redirectURL) {
		this.redirectURL = redirectURL;
	}

}
