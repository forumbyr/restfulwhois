package com.cnnic.whois.service;

import java.net.MalformedURLException;
import java.util.List;

import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.impl.CommonsHttpSolrServer;
import org.apache.solr.client.solrj.response.QueryResponse;

import com.cnnic.whois.bean.index.EntityIndex;
import com.cnnic.whois.bean.index.SearchCondition;
import com.cnnic.whois.service.index.SearchResult;
import com.cnnic.whois.util.WhoisProperties;

public class EntityIndexService {
	private static EntityIndexService indexService = new EntityIndexService(
			WhoisProperties.getEntitySolrUrl());
	private static final String ARRAY_SPLITER = "'~'";
	private static final String FUZZY_MARK = "*";
	private static final String Q_OR = " OR ";
	private CommonsHttpSolrServer server;

	public static EntityIndexService getIndexService() {
		return indexService;
	}

	/**
	 * 根据handle、name精确查询：registrar根据name查，其他类型的根据handle查询
	 * 
	 * @param searchCondition
	 * @return
	 */
	public SearchResult<EntityIndex> preciseQueryEntitiesByHandleOrName(
			String handleOrName) {
		handleOrName = handleOrName.replace(" ", "\\ ").replace(":", "\\:");
		String entityNamePrefix = "entityNames:";
		String entityNamesQ = entityNamePrefix + handleOrName;
		String entityNamesQP = entityNamePrefix + FUZZY_MARK + ARRAY_SPLITER
				+ handleOrName;
		String entityNamesQS = entityNamePrefix + handleOrName + ARRAY_SPLITER
				+ FUZZY_MARK;
		String entityNamesQPS = entityNamePrefix + FUZZY_MARK + ARRAY_SPLITER
				+ handleOrName + ARRAY_SPLITER + FUZZY_MARK;
		String entityNamesQFull = entityNamesQ + Q_OR + entityNamesQP + Q_OR
				+ entityNamesQS + Q_OR + entityNamesQPS;
		String queryStr = "(roles:registrar AND (" + entityNamesQFull + ")) "
				+ "OR (NOT roles:registrar AND handle:" + handleOrName + ")";
		queryStr = queryStr.replace("~", "\\~");
		SearchCondition searchCondition = new SearchCondition(queryStr);
		searchCondition.setRow(QueryService.MAX_SIZE_FUZZY_QUERY);
		return this.queryEntities(searchCondition);
	}

	public SearchResult<EntityIndex> fuzzyQueryEntitiesByHandleAndName(
			String fuzzyQueryParamName, String handleOrName) {
		handleOrName = handleOrName.replace(" ", "\\ ").replace(":", "\\:");
		String kVSplit = ":";
		String entityNamesQ = fuzzyQueryParamName +kVSplit+ handleOrName;
		String entityNamesQP = fuzzyQueryParamName + kVSplit+FUZZY_MARK + ARRAY_SPLITER
				+ handleOrName;
		String queryStr = entityNamesQ +Q_OR+ entityNamesQP;
		queryStr = queryStr.replace("~", "\\~");
		SearchCondition searchCondition = new SearchCondition(queryStr);
		searchCondition.setRow(QueryService.MAX_SIZE_FUZZY_QUERY);
		return this.queryEntities(searchCondition);
	}

	public SearchResult<EntityIndex> queryEntities(
			SearchCondition searchCondition) {
		SolrQuery solrQuery = new SolrQuery();
		solrQuery.setQuery(searchCondition.getSearchword());
		solrQuery.setStart(searchCondition.getStart());
		solrQuery.setRows(searchCondition.getRow());
		QueryResponse queryResponse = null;
		try {
			queryResponse = server.query(solrQuery);
		} catch (SolrServerException e) {
			e.printStackTrace();
		}
		SearchResult<EntityIndex> searchResult = new SearchResult<EntityIndex>();
		try {
			setSearchResult(searchResult, queryResponse);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return searchResult;
	}

	private void setSearchResult(SearchResult<EntityIndex> searchResult,
			QueryResponse queryResponse) {
		searchResult
				.setSearchTime((double) queryResponse.getElapsedTime() / 1000);
		searchResult.setTotalResults(queryResponse.getResults().getNumFound());
		List<EntityIndex> indexes = queryResponse.getBeans(EntityIndex.class);
		searchResult.setResultList(indexes);
	}

	public EntityIndexService(String url) {
		try {
			server = new CommonsHttpSolrServer(url);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}
}