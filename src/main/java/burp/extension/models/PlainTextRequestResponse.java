package burp.extension.models;

import java.util.List;


//processed request/response
public class PlainTextRequestResponse {
    
    private String fileName;
    private String urlPath;
    private String url;
    private String requestHeaders;
    private String requestBody;
    private String responseHeaders;
    private String responseBody;
    private String contentType;
    private String reqMethod;
    private List<String> comments;
    private List<String> forms;
    private List<String> inlineJS;
    private List<String> hiddenInputs;

    //Constructor
    public PlainTextRequestResponse(
        String fileName, String urlPath, String url, 
        String requestHeaders, String requestBody, 
        String responseHeaders, String responseBody, 
        String contentType, String reqMethod, 
        List<String> comments, List<String> forms, 
        List<String> inlineJS, List<String> hiddenInputs
    ) {
        this.fileName = fileName;
        this.urlPath = urlPath;
        this.url = url;
        this.requestHeaders = requestHeaders;
        this.requestBody = requestBody;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;
        this.contentType = contentType;
        this.reqMethod = reqMethod;
        this.comments = comments;
        this.forms = forms;
        this.inlineJS = inlineJS;
        this.hiddenInputs = hiddenInputs;
    }
    
    public String getFileName() { return fileName; }

}

