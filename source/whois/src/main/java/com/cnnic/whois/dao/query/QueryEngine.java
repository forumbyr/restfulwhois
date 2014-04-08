package com.cnnic.whois.dao.query;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.execption.RedirectExecption;
import com.cnnic.whois.permission.PermissionController;
import com.cnnic.whois.view.ResponseFilter;
import com.cnnic.whois.view.ViewResolver;
/**
 * query engine, call query executor for query .
 * 
 * @author nic
 *
 */
@Service
public class QueryEngine {
	private static QueryEngine engine = new QueryEngine();
	/**
	 * QueryExecutor has two implemention:db executor,and cache executor
	 * db and cache executor can replace each other,they all call solr executor for search
	 * following executor can replace each other:db and cache
	 */
	@Autowired
//	@Qualifier("cacheQueryExecutor")
	@Qualifier("dbQueryExecutor")
	private QueryExecutor queryExecutor;
	@Autowired
	private ViewResolver viewResolver ;
	@Autowired
	private ResponseFilter responseFilter;
	@Autowired
	private PermissionController permissionController ;

	/**
	 * get engine
	 * @return query engine
	 */
	public static QueryEngine getEngine() {
		return engine;
	}

	private void init() {
	}

	public QueryEngine() {
		super();
		init();
	}

	/**
	 * query main method
	 * @param queryType:query type
	 * @param param:query param
	 * @return query result map
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	public Map<String, Object> query(QueryType queryType, QueryParam param)
			throws QueryException, RedirectExecption {
		Map<String, Object> result = queryExecutor.query(queryType, param);
		result = permissionController.removeUnAuthedAndEmptyEntries(result);
		result = viewResolver.format(result, param.getFormat());
		result = responseFilter.removeNoticesEntries(result);
		return result;
	}
	
	/**
	 * format query result after query
	 * @param result:query result
	 * @param param:query param
	 * @return query result
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	public Map<String, Object> format(Map<String, Object> result, QueryParam param)
			throws QueryException, RedirectExecption {
		result = viewResolver.format(result, param.getFormat());
		return result;
	}
}
