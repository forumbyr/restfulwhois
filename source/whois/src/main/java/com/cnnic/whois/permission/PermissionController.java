package com.cnnic.whois.permission;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import net.sf.json.JSONArray;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.dao.query.db.DbQueryExecutor;
import com.cnnic.whois.util.AuthenticationHolder;
import com.cnnic.whois.util.WhoisUtil;
/**
 * permission controller,filter authorized column
 * @author nic
 *
 */
@Component
public class PermissionController {
	@Autowired
	private DbQueryExecutor dbQueryExecutor;
	/**
	 * remove unAuthed entries
	 * @param map
	 * @return
	 */
	public Map<String, Object> removeUnAuthedAndEmptyEntries(Map<String, Object> map) {
		String role = AuthenticationHolder.getAuthentication().getRole();
		if (null == map) {
			return map;
		}
		Object[] multiObjs = getMultiObjs(map);
		if (null != multiObjs) {
			removeUnAuthedEntriesObject(multiObjs, role);
			return map;
		}
		return removeUnAuthedEntriesMap(map, role);
	}
	/**
	 * remove unAuthed entries from map
	 * @param map :query result
	 * @param role :user role
	 * @return :filtered map
	 */
	private Map<String, Object> removeUnAuthedEntriesMap(
			Map<String, Object> map, String role) {
		if (null == map) {
			return map;
		}
		QueryType queryType = getQueryType(map);
		List<String> dnrKeyFields = dbQueryExecutor.getKeyFields(queryType,
				role);
		Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
		List<String> keyFieldsWithoutPrefix = this
				.removeFieldPrefix(dnrKeyFields);
		keyFieldsWithoutPrefix.add(WhoisUtil.RDAPCONFORMANCEKEY);
		keyFieldsWithoutPrefix.add(WhoisUtil.QUERY_TYPE);
		keyFieldsWithoutPrefix.add(WhoisUtil.QUERY_JOIN_TYPE);
		for (Iterator<Entry<String, Object>> it = map.entrySet().iterator(); it
				.hasNext();) {
			Entry<String, Object> entry = it.next();
			Object value = entry.getValue();
			if(null == value){
				continue;
			}
			if(value instanceof String && StringUtils.isBlank(value.toString())){
				continue;
			}
			boolean isEmptyArray = isStringArrayAndAllItemsAreEmpty(value);
			if(isEmptyArray){
				continue;
			}
			if (keyFieldsWithoutPrefix.contains(entry.getKey())) {
				resultMap.put(entry.getKey(), entry.getValue());
				removeUnAuthedEntriesObject(entry.getValue(), role);
			}
		}
		return resultMap;
	}
	
	/**
	 * check if param 'value' is an string array and all items are empty,eg :[""," "] 
	 * @param value
	 * @return boolean
	 */
	private boolean isStringArrayAndAllItemsAreEmpty(Object value) {
		if(null == value){
			return true;
		}
		boolean valueIsInstanceOfStringArray = value instanceof String[];
		if(! valueIsInstanceOfStringArray){
			return false;
		}
		boolean isEmptyArray = true;
		String[] valueArray = (String[]) value;
		for(String valueItem:valueArray){
			if(StringUtils.isNotBlank(valueItem)){
				isEmptyArray = false;
				break;
			}
		}
		return isEmptyArray;
	}

	/**
	 * get multi objects from query result map
	 * @param map:query result map
	 * @return:multi objects
	 */
	private Object[] getMultiObjs(Map<String, Object> map) {
		for (Iterator<Entry<String, Object>> it = map.entrySet().iterator(); it
				.hasNext();) {
			Entry<String, Object> entry = it.next();
			if (entry.getKey().startsWith(WhoisUtil.MULTIPRX)) {
				return (Object[]) entry.getValue();
			}
		}
		return null;
	}
	/**
	 * remove field prefix:$mul,$join
	 * @param fields
	 * @return field after removed prefix
	 */
	private List<String> removeFieldPrefix(List<String> fields) {
		List<String> result = new ArrayList<String>();
		for (String field : fields) {
			if (field.startsWith(WhoisUtil.JOINFILEDPRX)) {
				field = field.substring(WhoisUtil.JOINFILEDPRX.length());
			} else if (field.startsWith(WhoisUtil.MULTIPRX)) {
				field = field.substring(WhoisUtil.MULTIPRX.length());
			} else if (field.startsWith(WhoisUtil.ARRAYFILEDPRX)) {
				field = field.substring(WhoisUtil.ARRAYFILEDPRX.length());
			} else if (field.startsWith(WhoisUtil.EXTENDPRX)) {
				field = field.substring(WhoisUtil.EXTENDPRX.length());
			}
			result.add(field);
		}
		return result;
	}
	/**
	 * get query type from map
	 * @param map:query result
	 * @return query type
	 */
	private QueryType getQueryType(Map<String, Object> map) {
		Object queryTypeObj = map.get(WhoisUtil.QUERY_TYPE);
		if (null != queryTypeObj) {
			return QueryType.getQueryType((String) queryTypeObj);
		}
		return null;
	}
	/**
	 * remove unAuthed entries
	 * @param object:query result
	 * @param role :user role
	 */
	private void removeUnAuthedEntriesObject(Object object, String role) {
		if (null == object) {
			return;
		}
		if (object instanceof Object[]) {
			removeUnAuthedEntriesArray((Object[]) object, role);
		} else if (object instanceof JSONArray) {
			removeUnAuthedEntriesJsonArray((JSONArray) object, role);
		} else if (object instanceof Map) {
			Map<String, Object> map = (Map<String, Object>) object;
			Map<String, Object> result = removeUnAuthedEntriesMap(map, role);
			map.clear();
			map.putAll(result);
		}
	}
	/**
	 * remove unAuthed entries from jsonArray
	 * @param object :query result
	 * @param role :user role
	 */
	private void removeUnAuthedEntriesJsonArray(JSONArray object, String role) {
		for (int i = 0; i < object.size(); i++) {
			removeUnAuthedEntriesObject(object.get(i), role);
		}
	}
	/**
	 * remove unAuthed entries from array
	 * @param array:query result array
	 * @param role:user role
	 */
	private void removeUnAuthedEntriesArray(Object[] array, String role) {
		for (Object object : array) {
			removeUnAuthedEntriesObject(object, role);
		}
	}
}