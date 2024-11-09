import json
import re
import requests
from typing import Any, Dict
from hackingBuddyGPT.capabilities.http_request import HTTPRequest
from hackingBuddyGPT.usecases.web_api_testing.prompt_generation.information import PenTestingInformation
from hackingBuddyGPT.usecases.web_api_testing.prompt_generation.information.prompt_information import PromptPurpose
from hackingBuddyGPT.usecases.web_api_testing.utils.llm_handler import LLMHandler
from hackingBuddyGPT.utils import tool_message
import logging

logger = logging.getLogger(__name__)

class ResponseAnalyzerWithLLM:
    def __init__(self, purpose: PromptPurpose = None, llm_handler: LLMHandler = None):
        self.purpose = purpose
        self.llm_handler = llm_handler
        self.pentesting_information = PenTestingInformation()

    def analyze_response(self, raw_response: str, prompt_history: list) -> list:
        status_code, headers, body = self.parse_http_response(raw_response)
        full_response = f"Status Code: {status_code}\nHeaders: {json.dumps(headers, indent=4)}\nBody: {body}"
        llm_responses = []
        steps_dict = self.pentesting_information.analyse_steps(full_response)
        for purpose, steps in steps_dict.items():
            response = full_response
            for step in steps:
                prompt_history, response = self.process_step(step, prompt_history)
                llm_responses.append(response)
        return llm_responses

    def parse_http_response(self, raw_response: str):
        header_body_split = raw_response.split("\r\n\r\n", 1)
        header_lines = header_body_split[0].split("\n")
        body = header_body_split[1] if len(header_body_split) > 1 else ""
        status_line = header_lines[0].strip()
        match = re.match(r"HTTP/1\.1 (\d{3}) (.*)", status_line)
        status_code = int(match.group(1)) if match else None
        headers = {key.strip(): value.strip() for key, value in
                   (line.split(":", 1) for line in header_lines[1:] if ':' in line)}
        if body.startswith("<html"):
            body = ""
        elif status_code in [500, 400, 404, 422]:
            pass
        else:
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass
        return status_code, headers, body

    def process_step(self, step: str, prompt_history: list) -> tuple:
        prompt_history.append({"role": "system", "content": step})
        response, completion = self.llm_handler.call_llm(prompt_history)
        message = completion.choices[0].message
        prompt_history.append(message)
        tool_call_id = message.tool_calls[0].id
        try:
            result = response.execute()
        except Exception as e:
            result = f"Error executing tool call: {str(e)}"
        prompt_history.append(tool_message(str(result), tool_call_id))
        return prompt_history, result

if __name__ == '__main__':
    api_endpoint = 'http://localhost:8080/docs/'  
    def get_raw_response(url):
        response = requests.get(url)
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
        headers = '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.text
        raw_http_response = f"{status_line}\n{headers}\n\n{body}"
        return raw_http_response
    raw_http_response = get_raw_response(api_endpoint)
    capabilities = {
        "submit_http_method": HTTPRequest('http://localhost:8080/docs/'),
        "http_request": HTTPRequest('http://localhost:8080/docs/'),
    }
    # Assuming 'llm' is already initialized and has 'api_key' set
    # For example:
    from hackingBuddyGPT.utils.openai.openai_lib import OpenAILib
    llm = OpenAILib(api_key='getfromENV')
    llm_handler = LLMHandler(llm=llm, capabilities=capabilities)
    response_analyzer = ResponseAnalyzerWithLLM(
        purpose=PromptPurpose.PARSING,
        llm_handler=llm_handler
    )
    prompt_history = []
    results = response_analyzer.analyze_response(raw_http_response, prompt_history)
    for response in results:
        print(f"Response: {response}\n{'-'*50}")
