package com.cnnic.whois.service.admin;

import java.util.Arrays;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cnnic.whois.dao.admin.ExColumnDAO;
import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.ColumnCache;
import com.cnnic.whois.util.WhoisUtil;
/**
 * dynamic column service
 * @author nic
 *
 */
@Service
public class ExColumnService {
	
	@Autowired
	private ExColumnDAO exColumnDao;
	@Autowired
	private ColumnCache columnCache;

	/**
	 * Add the extension field
	 * 
	 * @param tableName
	 * @param columnMap
	 * @throws ManagementException
	 */
	public void addCoulumn(String tableName, Map<String, String> columnMap)
			throws ManagementException {
		exColumnDao.addCoulumn(tableName, columnMap);
		setColumnExtendList(tableName);
	}

	/**
	 * List extension field
	 * 
	 * @param tableName
	 * @return map collection
	 * @throws ManagementException
	 */
	public Map<String, String> listCoulumn(String tableName)
			throws ManagementException {
		return exColumnDao.listCoulumn(tableName);
	}

	/**
	 * Update the extension field
	 * 
	 * @param tableName
	 * @param oldColumnName
	 * @param newCloumnName
	 * @param columnLength
	 * @throws ManagementException
	 */
	public void updateCoulumn(String tableName, String oldColumnName,
			String newCloumnName, String columnLength)
			throws ManagementException {
		exColumnDao.updateCoulumn(tableName, oldColumnName, newCloumnName,
				columnLength);
		setColumnExtendList(tableName);

	}

	/**
	 * Delete the extension field
	 * 
	 * @param tableName
	 * @param columnName
	 * @throws ManagementException
	 */
	public void deleteCoulumn(String tableName, String columnName)
			throws ManagementException {
		exColumnDao.deleteCoulumn(tableName, columnName);
		setColumnExtendList(tableName);
	}

	/**
	 * When the extension field after the update is complete, call the method
	 * will be updated to add data to the ColumnCache cache
	 * 
	 * @param tableName
	 */
	private void setColumnExtendList(String tableName) {
		int typeBinary = Arrays.binarySearch(WhoisUtil.extendColumnTableTypes,
				tableName);
		switch (typeBinary) {
		case 0:
			columnCache.setASKeyFileds();
			break;
		case 1:
			columnCache.setDNRDomainKeyFileds();
			break;
		case 2:
			columnCache.setDNREntityKeyFileds();
			break;
		case 3:
			columnCache.setDsDataKeyFileds();
			break;
		case 4:
			columnCache.setErrorMessageKeyFileds();
			break;
		case 5:
			columnCache.setEventsKeyFileds();
			break;
		case 6:
			break;
		case 7:
			columnCache.setIPKeyFileds();
			break;
		case 8:
			columnCache.setKeyDataKeyFileds();
			break;
		case 9:
			columnCache.setLinkKeyFileds();
			break;
		case 10:
			columnCache.setNameServerKeyFileds();
			break;
		case 11:
			columnCache.setNoticesKeyFileds();
			break;
		case 12:
			columnCache.setPhonesKeyFileds();
			break;
		case 13:
			columnCache.setPostalAddressKeyFileds();
			break;
		case 14:
			columnCache.setPublicIdsKeyFileds();
			break;
		case 15:
			columnCache.setRegistrarKeyFileds();
			break;
		case 16:
			columnCache.setRemarksKeyFileds();
			break;
		case 17:
			columnCache.setRIRDomainKeyFileds();
			break;
		case 18:
			columnCache.setRIREntityKeyFileds();
			break;
		case 19:
			columnCache.setSecureDNSKeyFileds();
			break;
		case 20:
			columnCache.setVariantsKeyFileds();
			break;
		}
	}
}
