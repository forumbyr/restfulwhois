package com.cnnic.whois.bean;

import com.cnnic.whois.view.FormatType;

/**
 * ns query param bean
 * 
 * @author nic
 * 
 */
public class NsQueryParam extends QueryParam {
	/**
	 * ns punyname
	 */
	private String domainPuny;
	private String ip;// used for query ns by ip
	private boolean qByIp;// used for query ns by ip

	/**
	 * constuction
	 * 
	 * @param q
	 *            :query param
	 * @param domainPuny
	 *            :domain punycode
	 */
	public NsQueryParam(String q, String domainPuny) {
		super(q);
		this.domainPuny = domainPuny;
	}

	/**
	 * constuction
	 * 
	 * @param formatType
	 *            :response format type
	 * @param page
	 *            :page param
	 */
	public NsQueryParam(FormatType formatType, PageBean page) {
		super.setFormat(formatType);
		super.setPage(page);
	}

	/**
	 * get domain punycode
	 * 
	 * @return punycode
	 */
	public String getDomainPuny() {
		return domainPuny;
	}

	/**
	 * set domain punycode
	 * 
	 * @param domainPuny
	 *            :domain punycode
	 */
	public void setDomainPuny(String domainPuny) {
		this.domainPuny = domainPuny;
	}

	/**
	 * get ip
	 * 
	 * @return ip
	 */
	public String getIp() {
		return ip;
	}

	/**
	 * set ip
	 */
	public void setIp(String ip) {
		this.ip = ip;
	}

	/**
	 * get is query by ip
	 * 
	 * @return true if is by ip,false if not
	 */
	public boolean isqByIp() {
		return qByIp;
	}

	/**
	 * set query by ip
	 */
	public void setqByIp(boolean qByIp) {
		this.qByIp = qByIp;
	}
}