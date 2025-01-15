"""
Herbie - Security Testing Copilot with automated scanning capabilities.
"""
import os
import asyncio
from dotenv import load_dotenv
from semantic_kernel.kernel import Kernel
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
from semantic_kernel.agents import ChatCompletionAgent
from semantic_kernel.contents.chat_history import ChatHistory
from semantic_kernel.contents.utils.author_role import AuthorRole
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior

from herbie.plugins.scanning_plugin import ScanningPlugin
from herbie.plugins.nuclei_plugin import NucleiPlugin
from herbie.utils.logging_config import setup_logging, log_separator
import logging

# Set up logging
logger = setup_logging(console_level=logging.INFO, file_level=logging.DEBUG)

# Define agent configuration
AGENT_NAME = "Herbie"
AGENT_INSTRUCTIONS = """
You are Herbie, an advanced security testing copilot that specializes in:
1. Network Scanning with nmap
2. Advanced Vulnerability Scanning with nuclei

Your workflow involves:
1. Understanding the security testing requirements
2. Verifying target scope and permissions
3. Executing appropriate security scans
4. Analyzing and explaining results
5. Suggesting remediation steps

Guidelines:
- Always prioritize security and ethical considerations
- Verify target scope before scanning
- Provide clear explanations of findings
- Suggest remediation steps for vulnerabilities
- Handle errors gracefully and provide troubleshooting steps

When scanning is requested, always:
1. Confirm the target is in scope
2. Start with less intrusive scans
3. Gradually increase scan intensity if needed
4. Provide detailed analysis of results
"""

async def invoke_agent(agent: ChatCompletionAgent, input: str, chat: ChatHistory) -> None:
    """Invoke the agent with the user input."""
    chat.add_user_message(input)
    logger.info(f"# {AuthorRole.USER}: '{input}'")

    try:
        contents = []
        content_name = ""
        async for content in agent.invoke_stream(chat):
            content_name = content.name
            contents.append(content)
        message_content = "".join([content.content for content in contents])
        logger.info(f"# {content.role} - {content_name or '*'}: '{message_content}'")
        chat.add_assistant_message(message_content)
    except Exception as e:
        logger.error(f"Error during agent invocation: {str(e)}")
        raise

async def main():
    try:
        log_separator(logger, "Initializing Herbie Security Copilot", logging.INFO)
        
        # Load environment variables
        load_dotenv()
        
        # Azure OpenAI Configuration
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
        api_version = os.getenv("AZURE_API_VERSION")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")

        if not all([endpoint, deployment, api_version, api_key]):
            raise ValueError("Missing required Azure OpenAI environment variables")

        # Initialize kernel and configure AI service
        kernel = Kernel()
        service_id = "security_copilot"
        
        azure_chat_service = AzureChatCompletion(
            service_id=service_id,
            deployment_name=deployment,
            endpoint=endpoint,
            api_key=api_key,
            api_version=api_version
        )
        
        kernel.add_service(azure_chat_service)
        logger.info("Azure OpenAI service configured successfully")

        # Configure function choice behavior
        settings = kernel.get_prompt_execution_settings_from_service_id(service_id=service_id)
        settings.function_choice_behavior = FunctionChoiceBehavior.Auto()

        # Import plugins
        log_separator(logger, "Importing Security Plugins")
        kernel.add_plugin(ScanningPlugin(), plugin_name="scan")
        kernel.add_plugin(NucleiPlugin(), plugin_name="nuclei")
        logger.info("Security plugins imported successfully")

        # Create agent and chat history
        agent = ChatCompletionAgent(
            service_id=service_id,
            kernel=kernel,
            name=AGENT_NAME,
            instructions=AGENT_INSTRUCTIONS,
            execution_settings=settings
        )
        chat = ChatHistory()

        # Print welcome message
        logger.info("\nWelcome to Herbie - Your Security Testing Copilot!")
        logger.info("Available capabilities:")
        logger.info("- Network scanning with nmap")
        logger.info("- Advanced vulnerability scanning with nuclei")
        logger.info("Type 'exit' or 'quit' to end the session\n")

        # Interactive chat loop
        while True:
            user_input = input("\nYou:> ")
            if user_input.lower() in ['exit', 'quit']:
                break
            await invoke_agent(agent, user_input, chat)

    except ValueError as e:
        logger.error(str(e))
    except Exception as e:
        logger.exception("An error occurred during execution")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
        logger.info("Session ended successfully")
    except KeyboardInterrupt:
        logger.info("\nSession terminated by user")
    except Exception as e:
        logger.error(f"Session terminated with error: {str(e)}")
