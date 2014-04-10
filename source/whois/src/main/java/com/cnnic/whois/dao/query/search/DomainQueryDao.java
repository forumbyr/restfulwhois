package com.cnnic.whois.dao.query.search;

import com.cnnic.whois.bean.DomainQueryParam;
import com.cnnic.whois.bean.PageBean;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.bean.index.DomainIndex;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.index.SearchResult;
import com.cnnic.whois.util.validate.ValidateUtils;
/**
 * domain search dao
 * 
 * @author nic
 * 
 */
public class DomainQueryDao extends AbstractSearchQueryDao<DomainIndex> {

	/**
	 * construction
	 * 
	 * @param url
	 *            :solr core url
	 */
	public DomainQueryDao(String url) {
		super(url);
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.SEARCHDOMAIN;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return QueryType.SEARCHDOMAIN.equals(queryType);
	}

	@Override
	public SearchResult<DomainIndex> search(QueryParam param)
			throws QueryException {
		DomainQueryParam domainQueryParam = (DomainQueryParam) param;
		PageBean page = param.getPage();
		String q = domainQueryParam.getQ();
		String escapeQ = escapeSolrChar(q);
		String domainPuny = domainQueryParam.getDomainPuny();
		domainPuny = escapeSolrChar(domainPuny);
		String queryStr = "unicodeName:" + escapeQ;
		if (q.startsWith(ValidateUtils.ACE_PREFIX) || q.contains(ValidateUtils.ACE_PREFIX_INSIDE)) {
			queryStr = "ldhName:" + domainPuny + " OR " + queryStr;
		}
		SearchResult<DomainIndex> result = query(queryStr, page);
		return result;
	}
}
