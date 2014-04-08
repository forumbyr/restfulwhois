package com.cnnic.whois.bean;
/**
 * query join type when query join table
 * @author nic
 *
 */
public enum QueryJoinType {
	ENTITIES("entities"), NAMESERVER("nameServers"), DSDATA("dsData"), EVENTS(
			"events"), KEYDATA("keyData"), DELEGATIONKEYS("delegationKeys"), PUBLICIDS(
			"publicIds"), LINKS("links"), NOTICES("notices"), PHONES("phones"), POSTALADDRESS(
			"postalAddress"), REMARKS("remarks"), SECUREDNS("secureDNS"), VARIANTS(
			"variants");
	private String name;

	/**
	 * get query join type by name
	 * @param name
	 * @return
	 */
	public static QueryJoinType getQueryJoinType(String name) {
		QueryJoinType[] queryJoinTypes = QueryJoinType.values();
		for (QueryJoinType joinType : queryJoinTypes) {
			if (joinType.getName().equals(name)) {
				return joinType;
			}
		}
		return null;
	}

	/**
	 * construction
	 * @param name
	 */
	private QueryJoinType(String name) {
		this.setName(name);
	}
	
	/**
	 * get type name
	 * @return type name
	 */
	public String getName() {
		return name;
	}

	/**
	 * set type name
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
	}
}
