package com.cnnic.whois.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.cnnic.whois.bean.index.DomainIndex;
import com.cnnic.whois.bean.index.EntityIndex;
import com.cnnic.whois.bean.index.NameServerIndex;

public class PermissionCache {
	private static PermissionCache permissionCache = new PermissionCache();

	private Map<String, List<String>> IPMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> DNREntityMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> RIREntityMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> DNRDomainMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> RIRDomainMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> ASMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> NameServerMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> phonesMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> variantsMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> LinkMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> postalAddressMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> delegationMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> registrarMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> noticesMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> publicIdsMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> secureDNSMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> dsDataMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> keyDataMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> eventsMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> remarksMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> ErrorMessageMap = new HashMap<String, List<String>>();
	private Map<String, List<String>> helpMap = new HashMap<String, List<String>>();
	
	private ColumnCache columnCache = ColumnCache.getColumnCache();

	/**
	 * In the constructor to initialize the property value
	 */
	private PermissionCache() {
		IPMap = getKeyMap(WhoisUtil.IP, columnCache.getIPKeyFileds());
		DNREntityMap = getKeyMap(WhoisUtil.DNRENTITY,
				columnCache.getDNREntityKeyFileds());
		RIREntityMap = getKeyMap(WhoisUtil.RIRENTITY,
				columnCache.getRIREntityKeyFileds());
		DNRDomainMap = getKeyMap(WhoisUtil.DNRDOMAIN,
				columnCache.getDNRDomainKeyFileds());
		RIRDomainMap = getKeyMap(WhoisUtil.RIRDOMAIN,
				columnCache.getRIRDomainKeyFileds());
		ASMap = getKeyMap(WhoisUtil.AUTNUM, columnCache.getASKeyFileds());
		NameServerMap = getKeyMap(WhoisUtil.NAMESERVER,
				columnCache.getNameServerKeyFileds());
		phonesMap = getKeyMap(WhoisUtil.PHONES,
				columnCache.getPhonesKeyFileds());
		variantsMap = getKeyMap(WhoisUtil.VARIANTS,
				columnCache.getVariantsKeyFileds());
		LinkMap = getKeyMap(WhoisUtil.LINKS, columnCache.getLinkKeyFileds());
		postalAddressMap = getKeyMap(WhoisUtil.POSTALASSDESS,
				columnCache.getPostalAddressKeyFileds());
		//delegationMap = getKeyMap(WhoisUtil.DELEGATIONKEYS,
				//columnCache.getDelegationKeyFileds());
		registrarMap = getKeyMap(WhoisUtil.REGISTRAR,
				columnCache.getRegistrarKeyFileds());
		noticesMap = getKeyMap(WhoisUtil.NOTICES,
				columnCache.getNoticesKeyFileds());
		publicIdsMap = getKeyMap(WhoisUtil.PUBLICIDS,
				columnCache.getPublicIdsKeyFileds());
		secureDNSMap = getKeyMap(WhoisUtil.SECUREDNS,
				columnCache.getSecureDNSKeyFileds());
		dsDataMap = getKeyMap(WhoisUtil.DSDATA,
				columnCache.getDsDataKeyFileds());
		keyDataMap = getKeyMap(WhoisUtil.KEYDATA,
				columnCache.getKeyDataKeyFileds());
		remarksMap = getKeyMap(WhoisUtil.REMARKS,
				columnCache.getRemarksKeyFileds());
		eventsMap = getKeyMap(WhoisUtil.EVENTS,
				columnCache.getEventsKeyFileds());
		ErrorMessageMap = getKeyMap(WhoisUtil.ERRORMESSAGE,
				columnCache.getErrorMessageKeyFileds());
		helpMap = getKeyMap(WhoisUtil.HELP,
				columnCache.getHelpKeyFields());
	}

	/**
	 * Get PermissionCache objects
	 * 
	 * @return PermissionCache objects
	 */
	public static PermissionCache getPermissionCache() {
		return permissionCache;
	}

	/**
	 * Get IPKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getIPKeyFileds(String role) {
		return IPMap.get(role);
	}

	/**
	 * Set IPKeyFileds
	 */
	public void setIPMap() {
		IPMap = getKeyMap(WhoisUtil.IP, columnCache.getIPKeyFileds());
	}
	
	/**
	 * Get ErrorMessageKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getErrorMessageKeyFileds(String role) {
		return ErrorMessageMap.get(role);
	}
	
	/**
	 * Set ErrorMessageKeyFileds
	 */
	public void setErrorMessageMap() {
		ErrorMessageMap = getKeyMap(WhoisUtil.ERRORMESSAGE, columnCache.getIPKeyFileds());
	}

	/**
	 * Get DNREntityKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getDNREntityKeyFileds(String role) {
		return DNREntityMap.get(role);
	}

	/**
	 * Set DNREntityKeyFileds
	 */
	public void setDNREntityMap() {
		DNREntityMap = getKeyMap(WhoisUtil.DNRENTITY,
				columnCache.getDNREntityKeyFileds());
	}

	/**
	 * Get RIREntityKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getRIREntityKeyFileds(String role) {
		return RIREntityMap.get(role);
	}

	/**
	 * Set RIREntityKeyFileds
	 */
	public void setRIREntityMap() {
		RIREntityMap = getKeyMap(WhoisUtil.RIRENTITY,
				columnCache.getRIREntityKeyFileds());
	}

	/**
	 * Get DNRDomainKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getDNRDomainKeyFileds(String role) {
		return DNRDomainMap.get(role);
	}

	/**
	 * Set DNRDomainKeyFileds
	 */
	public void setDNRDomainMap() {
		DNRDomainMap = getKeyMap(WhoisUtil.DNRDOMAIN,
				columnCache.getDNRDomainKeyFileds());
	}

	/**
	 * Get RIRDomainKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getRIRDomainKeyFileds(String role) {
		return RIRDomainMap.get(role);
	}

	/**
	 * Set RIRDomainKeyFileds
	 */
	public void setRIRDomainMap() {
		RIRDomainMap = getKeyMap(WhoisUtil.RIRDOMAIN,
				columnCache.getRIRDomainKeyFileds());
	}

	/**
	 * Get ASKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getASKeyFileds(String role) {
		return ASMap.get(role);
	}

	/**
	 * Set ASKeyFileds
	 */
	public void setASMap() {
		ASMap = getKeyMap(WhoisUtil.AUTNUM, columnCache.getASKeyFileds());
	}

	/**
	 * Get NameServerKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getNameServerKeyFileds(String role) {
		return NameServerMap.get(role);
	}
	
	public List<String> getKeyFiledsByClass(Object o,String role) {
		if(o instanceof DomainIndex){
			if(((DomainIndex) o).isDnrDomain()){
				return getDNRDomainKeyFileds(role);
			}else{
				return getRIRDomainKeyFileds(role);
			}
		}
		if(o instanceof NameServerIndex){
			return getNameServerKeyFileds(role);
		}
		if(o instanceof EntityIndex){
			if(((EntityIndex) o).isDnrEntity()){
				return this.getDNREntityKeyFileds(role);
			}else{
				return this.getRIREntityKeyFileds(role);
			}
		}
		return new ArrayList<String>();
	}

	/**
	 * Set NameServerKeyFileds
	 */
	public void setNameServerMap() {
		NameServerMap = getKeyMap(WhoisUtil.NAMESERVER,
				columnCache.getNameServerKeyFileds());
	}

	/**
	 * Get PhonesKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getPhonesKeyFileds(String role) {
		return phonesMap.get(role);
	}

	/**
	 * Set PhonesKeyFileds
	 */
	public void setPhonesMap() {
		this.phonesMap = getKeyMap(WhoisUtil.PHONES,
				columnCache.getPhonesKeyFileds());
	}

	/**
	 * Get VariantsKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getVariantsKeyFileds(String role) {
		return variantsMap.get(role);
	}

	/**
	 * Set VariantsKeyFileds
	 */
	public void setVariantsMap() {
		this.variantsMap = getKeyMap(WhoisUtil.VARIANTS,
				columnCache.getVariantsKeyFileds());
	}

	/**
	 * Get LinkKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getLinkKeyFileds(String role) {
		return LinkMap.get(role);
	}

	/**
	 * Set LinkKeyFileds
	 */
	public void setLinkMap() {
		LinkMap = getKeyMap(WhoisUtil.LINKS, columnCache.getLinkKeyFileds());
	}

	/**
	 * Get PostalAddressKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getPostalAddressKeyFileds(String role) {
		return postalAddressMap.get(role);
	}

	/**
	 * Set PostalAddressKeyFileds
	 */
	public void setPostalAddressMap() {
		this.postalAddressMap = getKeyMap(WhoisUtil.POSTALASSDESS,
				columnCache.getPostalAddressKeyFileds());
	}

	/**
	 * Get DelegationKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getDelegationKeyFileds(String role) {
		return delegationMap.get(role);
	}

	/**
	 * Set DelegationKeyFileds
	 */
	public void setDelegationMap() {
		this.delegationMap = getKeyMap(WhoisUtil.DELEGATIONKEYS,
				columnCache.getDelegationKeyFileds());
	}

	/**
	 * Get RegistrarKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getRegistrarKeyFileds(String role) {
		return registrarMap.get(role);
	}

	/**
	 * Set RegistrarKeyFileds
	 */
	public void setRegistrarMap() {
		this.registrarMap = getKeyMap(WhoisUtil.REGISTRAR,
				columnCache.getRegistrarKeyFileds());
	}

	/**
	 * Get NoticesKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getNoticesKeyFileds(String role) {
		return noticesMap.get(role);
	}

	/**
	 * Set NoticesKeyFileds
	 */
	public void setNoticesMap() {
		this.noticesMap = getKeyMap(WhoisUtil.NOTICES,
				columnCache.getNoticesKeyFileds());
	}
	
	/**
	 * Get PublicIdsKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getPublicIdsKeyFileds(String role) {
		return publicIdsMap.get(role);
	}

	/**
	 * Set PublicIdsKeyFileds
	 */
	public void setPublicIdsMap() {
		this.publicIdsMap = getKeyMap(WhoisUtil.PUBLICIDS,
				columnCache.getPublicIdsKeyFileds());
	}
	
	/**
	 * Get SecureDNSMapKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getSecureDNSMapKeyFileds(String role) {
		return secureDNSMap.get(role);
	}

	/**
	 * Set SecureDNSMapKeyFileds
	 */
	public void setSecureDNSMap() {
		this.secureDNSMap = getKeyMap(WhoisUtil.SECUREDNS,
				columnCache.getSecureDNSKeyFileds());
	}
	
	/**
	 * Get DsDataMapKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getDsDataMapKeyFileds(String role) {
		return dsDataMap.get(role);
	}

	/**
	 * Set DsDataMapKeyFileds
	 */
	public void setDsDataMap() {
		this.dsDataMap = getKeyMap(WhoisUtil.DSDATA,
				columnCache.getDsDataKeyFileds());
	}
	
	/**
	 * Get KeyDataMapKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getKeyDataMapKeyFileds(String role) {
		return keyDataMap.get(role);
	}

	/**
	 * Set DsDataMapKeyFileds
	 */
	public void setKeyDataMap() {
		this.keyDataMap = getKeyMap(WhoisUtil.KEYDATA,
				columnCache.getKeyDataKeyFileds());
	}
	
	/**
	 * Get EventsKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getEventsKeyFileds(String role) {
		return eventsMap.get(role);
	}
	/**
	 * Set EventsKeyFileds
	 */
	public void setEventsMap() {
		this.eventsMap = getKeyMap(WhoisUtil.EVENTS,
				columnCache.getEventsKeyFileds());
	}
	/**
	 * Get RemarksKeyFileds
	 * 
	 * @param role
	 * @return List
	 */
	public List<String> getRemarksKeyFileds(String role) {
		return remarksMap.get(role);
	}
	/**
	 * Set RemarksKeyFileds
	 */
	public void setRemarksMap() {
		this.remarksMap = getKeyMap(WhoisUtil.REMARKS,
				columnCache.getRemarksKeyFileds());
	}

	/**
	 * Collection to obtain the proper permission and the field that map collection
	 * 
	 * @param tableName
	 * @param coulumNameList
	 * @return Map
	 */
	private Map<String, List<String>> getKeyMap(String tableName,
			List<String> coulumNameList) {
		Map<String, List<String>> keyMap = new HashMap<String, List<String>>();
		List<String> anonymousDataList = new ArrayList<String>();
		List<String> authenticatedDataList = new ArrayList<String>();
		List<String> rootDataList = new ArrayList<String>();
		
		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(WhoisUtil.JNDI_NAME);
			Connection connection = ds.getConnection();
			PreparedStatement stmt = connection
					.prepareStatement(WhoisUtil.SELECT_PERMISSION);
			stmt.setString(1, tableName);
			ResultSet results = stmt.executeQuery();

			while (results.next()) {
				String column = results.getString("columnName");
				if (results.getString("anonymous").equals("1"))
					anonymousDataList.add(column);

				if (results.getString("authenticated").equals("1"))
					authenticatedDataList.add(column);

				if (results.getString("root").equals("1"))
					rootDataList.add(column);
			}

			List<String> anonymousList = new ArrayList<String>();
			List<String> authenticatedList = new ArrayList<String>();
			List<String> rootList = new ArrayList<String>();

			for (String allcoulumn : coulumNameList) {
				for (String coulumn : anonymousDataList) {
					if (allcoulumn.equals(coulumn)) {
						anonymousList.add(coulumn);
						break;
					}
				}

				for (String coulumn : authenticatedDataList) {

					if (allcoulumn.equals(coulumn)) {

						authenticatedList.add(coulumn);
						break;
					}
				}

				for (String coulumn : rootDataList) {
					if (allcoulumn.equals(coulumn)) {
						rootList.add(coulumn);
						break;
					}
				}

			}
			keyMap.put("anonymous", anonymousList);
			keyMap.put("authenticated", authenticatedList);
			keyMap.put("root", rootList);
			
			return keyMap;
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalStateException(e.getMessage());
		}

	}

	public List<String> getHelpKeyFileds(String role) {
		return helpMap.get(role);
	}
	
	public void setHelpMap() {
		this.helpMap = getKeyMap(WhoisUtil.HELP,
				columnCache.getHelpKeyFields());
	}
}
