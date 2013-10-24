package com.cnnic.whois.bean.index;

import java.util.HashMap;
import java.util.Map;

import org.apache.solr.client.solrj.beans.Field;

public class EntityIndex implements Index {
	private static String DNRENTITY_TYPE = "dnrEntity";
	private static String RIRENTITY_TYPE = "rirEntity";
	
	@Field("docType")
	private String docType;
	@Field("handle")
	private String handle;
	@Field("entityNames")
	private String entityNames;
	/**
	 * rnr entity begin
	 */
	@Field("status")
	private String status;
	@Field("port43")
	private String port43;
	/**
	 * rnr entity end
	 */
	@Field("roles")
	private String roles;
	@Field("emails")
	private String emails;
	@Field("lang")
	private String lang;
	@Field("bday")
	private String bday;
	@Field("anniversary")
	private String anniversary;
	@Field("gender")
	private String gender;
	@Field("kind")
	private String kind;
	@Field("languageTag1")
	private String languageTag1;
	@Field("languageTag2")
	private String languageTag2;
	@Field("pref1")
	private String pref1;
	@Field("pref2")
	private String pref2;
	@Field("org")
	private String org;
	@Field("title")
	private String title;
	@Field("role")
	private String role;
	@Field("geo")
	private String geo;
	@Field("key")
	private String key;
	@Field("tz")
	private String tz;
	@Field("url")
	private String url;
	private Map<String, String> propValueMap = new HashMap<String, String>();

	public boolean isDnrEntity(){
		return DNRENTITY_TYPE.equals(docType);
	}
	
	public String getPropValue(String key) {
		return propValueMap.get(key);
	}

	public EntityIndex() {
	}

	public void initPropValueMap() {
		propValueMap.put("Handle", this.handle);
		propValueMap.put("Entity_Names", this.entityNames);
		propValueMap.put("Status", this.status);
		propValueMap.put("Emails", this.emails);
		propValueMap.put("Port43", this.port43);
		propValueMap.put("Roles", this.roles);
		propValueMap.put("Lang", this.lang);
		propValueMap.put("Bday", this.bday);
		propValueMap.put("Anniversary", this.anniversary);
		propValueMap.put("Gender", this.gender);
		propValueMap.put("Kind", this.kind);
		propValueMap.put("Language_Tag_1", this.languageTag1);
		propValueMap.put("Language_Tag_2", this.languageTag2);
		propValueMap.put("Pref1", this.pref1);
		propValueMap.put("Pref2", this.pref2);
		propValueMap.put("Org", this.org);
		propValueMap.put("Title", this.title);
		propValueMap.put("Role", this.role);
		propValueMap.put("Geo", this.geo);
		propValueMap.put("Key", this.key);
		propValueMap.put("Tz", this.tz);
		propValueMap.put("Url", this.url);
	}

	@Override
	public String getHandle() {
		return this.handle;
	}

	@Override
	public String getDocType() {
		return this.docType;
	}
}