package com.cnnic.whois.view;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import net.sf.json.JSONArray;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.cnnic.whois.dao.query.db.DbQueryExecutor;
import com.cnnic.whois.util.WhoisUtil;
/**
 * filter special key in result map,eg :notices can't be non top key of result map
 * @author nic
 *
 */
@Component
public class ResponseFilter {
	@Autowired
	private DbQueryExecutor dbQueryExecutor;

	/**
	 * remove non-top notice entries in query result map
	 * @param map
	 * @return map
	 */
	public Map<String, Object> removeNonTopNoticesEntries(Map<String, Object> map) {
		if (null == map) {
			return map;
		}
		for (Iterator<Entry<String, Object>> it = map.entrySet().iterator(); it
				.hasNext();) {
			Entry<String, Object> entry = it.next();
			removeNonTopNoticeEntriesObject(entry.getValue());
		}
		return map;
	}

	/**
	 * remove notice for map
	 * @param map
	 * @return map
	 */
	private Map<String, Object> removeNonTopNoticeEntriesMap(
			Map<String, Object> map) {
		if (null == map) {
			return map;
		}
		Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
		for (Iterator<Entry<String, Object>> it = map.entrySet().iterator(); it
				.hasNext();) {
			Entry<String, Object> entry = it.next();
			if (!entry.getKey().equals(WhoisUtil.NOTICES)) {
				resultMap.put(entry.getKey(), entry.getValue());
				removeNonTopNoticeEntriesObject(entry.getValue());
			}
		}
		return resultMap;
	}

	/**
	 * remove notice for object
	 * @param object
	 */
	private void removeNonTopNoticeEntriesObject(Object object) {
		if (null == object) {
			return;
		}
		if (object instanceof Object[]) {
			removeUnAuthedEntriesArray((Object[]) object);
		} else if (object instanceof JSONArray) {
			removeNonTopNoticeEntriesJsonArray((JSONArray) object);
		} else if (object instanceof Map) {
			Map<String, Object> map = (Map<String, Object>) object;
			Map<String, Object> result = removeNonTopNoticeEntriesMap(map);
			map.clear();
			map.putAll(result);
		}
	}

	/**
	 * remove notice for json array
	 * @param object
	 */
	private void removeNonTopNoticeEntriesJsonArray(JSONArray object) {
		for (int i = 0; i < object.size(); i++) {
			removeNonTopNoticeEntriesObject(object.get(i));
		}
	}

	/**
	 * remove notice for object array
	 * @param array
	 */
	private void removeUnAuthedEntriesArray(Object[] array) {
		for (Object object : array) {
			removeNonTopNoticeEntriesObject(object);
		}
	}
}