package org.ecocean;

import org.ecocean.Util;
import org.ecocean.media.MediaAsset;
import org.json.JSONObject;

import java.util.List;
import javax.jdo.Query;
import java.util.HashMap;


public class WBQuery implements java.io.Serializable {

    private static final long serialVersionUID = -7934850478934029842L;

    protected JSONObject parameters;
    protected String className;
    protected long id;
    protected String parametersAsString;
    protected String name;
    protected AccessControl owner;
    protected long revision;


    public WBQuery() {
    }

    public WBQuery(final int id, final JSONObject params, final AccessControl owner) {
        this.id = id;
        System.out.println("initializing QBQuery with id = "+this.id);
        System.out.println("init params = "+params.toString());
        this.owner = owner;
        this.className = params.optString("class");
        System.out.println("className = "+this.className);
        this.parameters = params.optJSONObject("query");
        System.out.println("parameters = "+this.parameters.toString());
        if (params != null) this.parametersAsString = params.toString();
        this.setRevision();
    }

    public WBQuery(final JSONObject params) {
        this(-1, params, null);
    }

    public WBQuery(final JSONObject params, final AccessControl owner) {
        this(-1, params, owner);
    }

    public JSONObject getParameters() {
        if (parameters != null) return parameters;
        //System.out.println("NOTE: getParameters() on " + this + " was null, so trying to get from parametersAsString()");
        JSONObject j = Util.stringToJSONObject(parametersAsString);
        parameters = j;
        return j;
    }

    public void setParameters(JSONObject p) {
        if (p == null) {
            //System.out.println("WARNING: attempted to set null parameters on " + this + "; ignoring");
            return;
        }
        parameters = p;
        parametersAsString = p.toString();
    }

    //this *should* magically return a List of the proper classed object. good luck with that!
    public List<Object> doQuery(Shepherd myShepherd) throws RuntimeException {
        Query query = toQuery(myShepherd);
        return (List<Object>) query.execute();
    }


/* something like this?
    WBQuery qry = new WBQuery(new JSONObject("{ \"foo\" : \"bar\" }"));
    List<Object> res = qry.doQuery(myShepherd);
*/
    public Query toQuery(Shepherd myShepherd) throws RuntimeException {
        Query query = null;
        try {  //lets catch any shenanigans that happens here, and throw our own RuntimeException
            query = myShepherd.getPM().newQuery(toJDOQL());
            query.setClass(getCandidateClass());
            querySetRange(query);
            querySetOrdering(query);
        } catch (Exception ex) {
            throw new RuntimeException(ex.toString());
        }
        return query;
    }

    //TODO
    public String toJDOQL() {
        /////getParameters() will give the JSONObject we need to magically turn into JDOQL!!
        String output = "SELECT FROM "+className+" WHERE ";
        String[] names = JSONObject.getNames(parameters);
        String[] parsedFields = new String[names.length];
        for (int i=0; i<names.length; i++) {
          parsedFields[i]=parseField(names[i]);
        }
        output += "(" + joinString(parsedFields, " && ") + ")";

        return output;
    }

    public Class getCandidateClass() throws java.lang.ClassNotFoundException {
        if (className == null) throw new ClassNotFoundException("missing class name in query");
        return Class.forName(className);  //this also will throw Exception if no good
    }

    //TODO
    public void querySetRange(Query query) {
        query.setRange(0,10);
    }

    //TODO
    public void querySetOrdering(Query query) {
        query.setOrdering("id DESC");
    }

    public long setRevision() {
        this.revision = System.currentTimeMillis();
        return this.revision;
    }

    /**
     *  parses a single field from this query's own params -- returns JDOQL. This corresponds to a single class field.
     */
    private String parseField(String field) {

      System.out.println("parsing field "+field);

      String output = "(";
      try {
        String valueClass = parameters.opt(field).getClass().getName();
        System.out.println("it has valueClass "+valueClass);
        switch(valueClass) {
          case "java.lang.String": {
            // This is the simple case of field: value
            output += field+" == "+parameters.getString(field);
            break;
          }
          case "org.json.JSONObject": {
            // This case deals with operators such as $ne and $and
            JSONObject value = parameters.getJSONObject(field);
            output += parseOperatorField(field);
            break;
          }
          default: {
            output += field+": ERROR PARSING VALUE CLASS "+valueClass;
          }
        }
      }
      catch (Exception e) {
        System.out.println("Exception found parsing field "+field+".");
        e.printStackTrace();
      }
      output+=")";
      return output;
    }

    // TODO:
    private String parseOperatorField(String field) throws NullPointerException {

      String output = "";
      JSONObject fieldQuery = parameters.optJSONObject(field);
      String[] operators = JSONObject.getNames(fieldQuery);
      String[] values = new String[operators.length];
      for (int i=0; i<operators.length; i++) {
        String operator = operators[i];
        String value = fieldQuery.optString(operator, "PARSE-ERROR");
        if (comparisonOperator.containsKey(operator)) {

          output += comparisonOperator.get(operator).execute(field, value);

        }
      }
      return output;//" operators = ("+output+"): ( (not parsable)" + fieldQuery.toString() + ")";
    }

    private static String parseOperator(String field, String operator, String value) {
      return "this isn't ready yet OK!";
    }

    /**
     *  parses a single field -- returns JDOQL
     */
    private static String parseField(String field, String value) {
      return ("("+field+"==\""+value+"\")");
    }


    private static String joinString (String[] strings, String glue) {
      if (strings.length==0) return "";
      String res = strings[0];
      for (int i=1; i<strings.length; i++) {
        res += glue + strings[i];
      }
      return res;
    }

    private static String buildComparisonOperator(String field, String operator, String value) {
      return field+' '+operator+' '+value;
    }

    private static String buildBooleanOperator(String field, String operator, String value) {
      String isNot = "";
      if (value!="true") isNot=" not"; //TODO: double-check the logic on this line once we have examples
      return buildComparisonOperator(field, "is"+isNot, value);
    }


    private static String buildLogicalOperator(String operator, String[] values) {
      String result = joinString(values, ' ' + operator + ' ');
      if (values.length > 1) result = '(' + result + ')';
      return result;
    }

    interface CompOperator {
      String inverseOp();
      String execute(String field, String value);
    }



    // the below stuff is literally in the WBQuery instance initializer
    private static HashMap<String, CompOperator> comparisonOperator = new HashMap<String, CompOperator>();
    {
      comparisonOperator.put("$eq", new CompOperator() {
        public String inverseOp() {return "$ne";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, "=", value));
        }
      });
      comparisonOperator.put("$ne", new CompOperator() {
        public String inverseOp() {return "$eq";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, "!=", value));
        }
      });
      comparisonOperator.put("$lt", new CompOperator() {
        public String inverseOp() {return "$gte";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, "<", value));
        }
      });
      comparisonOperator.put("$gt", new CompOperator() {
        public String inverseOp() {return "$lte";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, ">", value));
        }
      });
      comparisonOperator.put("$lte", new CompOperator() {
        public String inverseOp() {return "$gt";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, "<=", value));
        }
      });
      comparisonOperator.put("$gte", new CompOperator() {
        public String inverseOp() {return "$lt";}
        public String execute(String field, String value) {
          return (buildComparisonOperator(field, ">=", value));
        }
      });
    }

    interface LogicOperator {
      String execute(String[] values);
    }
    HashMap<String, LogicOperator> logicalOperator = new HashMap<String, LogicOperator>();
    {
      logicalOperator.put("$and", new LogicOperator() {
        public String execute(String[] values) {
          return buildLogicalOperator("and", values);
        }
      });
      logicalOperator.put("$or", new LogicOperator() {
        public String execute(String[] values) {
          return buildLogicalOperator("or", values);
        }
      });
    }




    /*
    public <E> void modList(List<? extends E> list, Operation<E> op) {
      for (E elem : list)
        op.execute(elem);
    }

    modList(pList, new Operation<Person>() {
        public void execute(Person p) { p.setAge(p.getAge() + 1); }
    });


    // this section contains helper functinos for toJDOQL
    private static HashMap operators() {

      String buildComparisonOperator(String field, String operator, String value) {

      }

      HashMap<String,HashMap> operators = new HashMap<String,HashMap>();

      HashMap eq = new HashMap();
      eq.put("inversedOperator","$ne");
    }
    */
}
