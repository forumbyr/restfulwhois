package com.cnnic.whois.bean.index;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.solr.client.solrj.beans.Field;

import com.cnnic.whois.bean.Domain;

public class DomainIndex implements Index{
	private static String DNRDOMAIN_TYPE = "dnrDomain";
	private static String RIRDOMAIN_TYPE = "rirDomain";

	@Field("id")
	private String id;
	@Field("docType")
	private String docType;
	@Field("handle")
	private String handle;
	@Field("ldhName")
	private String ldhName;
	@Field("status")
	private String status;
	@Field("port43")
	private String port43;
	@Field("lang")
	private String lang;
	@Field("unicodeName")
	private String unicodeName;
	private Map<String,String> propValueMap = new HashMap<String,String>();

	private Domain domain;

	public boolean isDnrDomain(){
		return DNRDOMAIN_TYPE.equals(docType);
	}
	
	public String getPropValue(String key){
		return propValueMap.get(key);
	}
	public DomainIndex(Domain domain) {
		this.domain = domain;
		try {
			BeanUtils.copyProperties(this, domain);
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public DomainIndex() {
	}

	public void initPropValueMap() {
		propValueMap.put("Handle", this.handle);
		propValueMap.put("Ldh_Name", this.ldhName);
		propValueMap.put("Unicode_Name", this.unicodeName);
		propValueMap.put("Lang", this.lang);
		propValueMap.put("Port43", this.port43);
		propValueMap.put("Status", this.status);
	}
	public Domain getDomainBean() {
		if (domain == null) {
			domain = new Domain();
			domain.setId(id);
			domain.setDocType(docType);
			domain
					.setHandle(handle);
			domain
					.setLang(lang);
			domain
					.setLdhName(ldhName);
			domain
					.setPort43(port43);
			domain
					.setStatus(status);
			domain
					.setUnicodeName(unicodeName);
			propValueMap.put("Handle", this.handle);
			propValueMap.put("Ldh_Name", this.ldhName);
			propValueMap.put("Unicode_Name", this.unicodeName);
			propValueMap.put("Lang", this.lang);
			propValueMap.put("Port43", this.port43);
		}
		return domain;
	}

	public String getHandle() {
		return handle;
	}

	public void setHandle(String handle) {
		this.handle = handle;
	}

	public String getLdhName() {
		return ldhName;
	}

	public void setLdhName(String ldhName) {
		this.ldhName = ldhName;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getPort43() {
		return port43;
	}

	public void setPort43(String port43) {
		this.port43 = port43;
	}

	public String getLang() {
		return lang;
	}

	public void setLang(String lang) {
		this.lang = lang;
	}

	public String getUnicodeName() {
		return unicodeName;
	}

	public void setUnicodeName(String unicodeName) {
		this.unicodeName = unicodeName;
	}

	public Domain getDomain() {
		return domain;
	}

	public void setDomain(Domain domain) {
		this.domain = domain;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getDocType() {
		return docType;
	}

	public void setDocType(String docType) {
		this.docType = docType;
	}
}