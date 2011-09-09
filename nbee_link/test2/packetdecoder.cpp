/*
 * Copyright (c) 2002 - 2011
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following condition 
 * is met:
 * 
 * Neither the name of the Politecnico di Torino nor the names of its 
 * contributors may be used to endorse or promote products derived from 
 * this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <nbee.h>
#include "../common/measure.h"			// Code for measurement
#include "nbee_link.h"

#include "/home/rdenicol/git/of11softswitch/lib/hmap.h"
#include "/home/rdenicol/git/of11softswitch/lib/bj_hash.h"
#include "/home/rdenicol/git/of11softswitch/include/openflow/match-ext.h"


#define PDMLFILE "pdmlout.xml"
#define PSMLFILE "psmlout.xml"


// Global variables for configuration
int ShowNetworkNames;
char* NetPDLFileName;
char* CaptureFileName;
int DecodingType;
int StoreRawDump;

static struct hmap all_packet_fields = HMAP_INITIALIZER(&all_packet_fields);

enum {
	DECODEALL_AND_SAVE = 0,
	DECODE_AND_SAVE,
	DECODE_NOSAVE,
	DECODEALL_NOSAVE
};


void Usage()
{
char string[]= \
	"\nUsage:\n"	\
	"  packetdecoder [options]\n\n"	\
	"Options:\n"	\
	" -shownetworknames: shows network names (e.g. www.foo.com) instead of IP\n"		\
	"     addresses in the decoded file. Default: disabled.\n"							\
	" -netpdl FileName: name (and *path*) of the file containing the NetPDL\n"			\
	"     description. In case it is omitted, the NetPDL description embedded\n"		\
	"     within the NetBee library will be used.\n"									\
	" -capturefile FileName: name (and *path*) of the file containing the packet\n"		\
	"     dump that has to be decoded. If missing, file 'samplecapturedump.acp'\n"		\
	"     will be used.\n"																\
	" -mindecode: this program dumps the PDML result on file, but it uses\n"			\
	"     a minimal database, which excludes visualization primitives.\n"				\
	"     Please note that the PSML will not be generated.\n"							\
	"     Useful mostly when using a reduced version of the database.\n"				\
	" -mindecode_nosave: this program does not save any PDML/PSML result on file.\n"	\
	"     In addition, it uses a minimal database, which excludes visualization\n"		\
	"     primitives. Useful mostly for debug/performance purposes.\n"					\
	" -fulldecode_nosave: this program does not save any PDML/PSML result \n"			\
	"     on file. However, the complete decoding (i.e. including visualization\n"		\
	"     primitives) is done. Useful mostly for debug/performance purposes.\n"			\
	" -rawdump: in addition to the previous options, this switch will enable the\n"		\
	"     generation of the raw dump in the PDML fragments \n"							\
	" -h: prints this help message.\n\n"												\
	"Description\n"																		\
	"============================================================================\n"	\
	"This program shows how to use the NetBee Packet Decoder and to dump the result\n"	\
	"  on disk.\n"																		\
	"This program opens a capture dump file, it decodes all the packets, and it\n"		\
	"  creates the corresponding PSML and PDML files (named '" PDMLFILE "' and \n"		\
	"  '" PSMLFILE "' that are saved on disk in the current folder.\n"					\
	"By default, it creates the PDML/PSML fragments using NetPDL visualization\n"		\
	"  primitives.\n\n";

	printf("%s", string);
}


int ParseCommandLine(int argc, char *argv[])
{
int CurrentItem;
	
	CurrentItem= 1;

	while (CurrentItem < argc)
	{
		if (strcmp(argv[CurrentItem], "-shownetworknames") == 0)
		{
			ShowNetworkNames= 1;
			CurrentItem++;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-netpdl") == 0)
		{
			NetPDLFileName= argv[CurrentItem+1];
			CurrentItem+= 2;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-capturefile") == 0)
		{
			CaptureFileName= argv[CurrentItem+1];
			CurrentItem+= 2;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-mindecode") == 0)
		{
			if (DecodingType)
			{
				printf("Error: option '%s' cannot be used with '-mindecode_nosave' or '-fulldecode_nosave'.\n", argv[CurrentItem]);
				return nbFAILURE;
			}
			DecodingType= DECODE_AND_SAVE;
			CurrentItem++;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-mindecode_nosave") == 0)
		{
			if (DecodingType)
			{
				printf("Error: option '%s' cannot be used with '-mindecode' or '-fulldecode_nosave'.\n", argv[CurrentItem]);
				return nbFAILURE;
			}
			DecodingType= DECODE_NOSAVE;
			CurrentItem++;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-fulldecode_nosave") == 0)
		{
			if (DecodingType)
			{
				printf("Error: option '%s' cannot be used with '-mindecode' or '-mindecode_nosave'.\n", argv[CurrentItem]);
				return nbFAILURE;
			}
			DecodingType= DECODEALL_NOSAVE;
			CurrentItem++;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-rawdump") == 0)
		{
			StoreRawDump= 1;
			CurrentItem++;
			continue;
		}

		if (strcmp(argv[CurrentItem], "-h") == 0)
		{
			Usage();
			return nbFAILURE;
		}

		printf("Error: parameter '%s' is not valid.\n", argv[CurrentItem]);
		return nbFAILURE;
	}

	return nbSUCCESS;
}


int main(int argc, char *argv[])
{
nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbPacketDumpFilePcap* PcapPacketDumpFile;
char ErrBuf[PCAP_ERRBUF_SIZE + 1];
char Buffer[2048];
nbNetPDLLinkLayer_t LinkLayerType;
int PacketCounter= 1;
int NetPDLProtoDBFlags;
int NetPDLDecoderFlags;

	if (ParseCommandLine(argc, argv) == nbFAILURE)
		return nbFAILURE;

	printf("\n\nLoading NetPDL protocol database...\n");

	if ((DecodingType == DECODEALL_AND_SAVE) || (DecodingType == DECODEALL_NOSAVE))
		NetPDLProtoDBFlags= nbPROTODB_FULL;
	else
		NetPDLProtoDBFlags= nbPROTODB_MINIMAL;

	if (NetPDLFileName)
	{
	int Res;

		Res= nbInitialize(NetPDLFileName, NetPDLProtoDBFlags, ErrBuf, sizeof(ErrBuf) );

		if (Res == nbFAILURE)
		{
			printf("Error initializing the NetBee Library; %s\n", ErrBuf);
			printf("\n\nUsing the NetPDL database embedded in the NetBee library instead.\n");
		}
	}

	// In case the NetBee library has not been initialized,
	// initialize right now with the embedded NetPDL protocol database instead
	if (nbIsInitialized() == nbFAILURE)
	{
		if (nbInitialize(NULL, NetPDLProtoDBFlags, ErrBuf, sizeof(ErrBuf)) == nbFAILURE)
		{
			printf("Error initializing the NetBee Library; %s\n", ErrBuf);
			return nbFAILURE;
		}
	}

	printf("NetPDL Protocol database loaded.\n");

	if (StoreRawDump)
		NetPDLDecoderFlags= nbDECODER_GENERATEPDML_RAWDUMP;
	else
		NetPDLDecoderFlags= 0;

	// Create a NetPDL Parser to decode packet
	switch(DecodingType)
	{
		case DECODE_NOSAVE:
		{
			NetPDLDecoderFlags|= nbDECODER_GENERATEPDML;
		}; break;

		case DECODE_AND_SAVE:
		{
			NetPDLDecoderFlags|= (nbDECODER_GENERATEPDML | nbDECODER_KEEPALLPDML);
		}; break;

		case DECODEALL_NOSAVE:
		{
			NetPDLDecoderFlags|= (nbDECODER_GENERATEPDML_COMPLETE | nbDECODER_GENERATEPSML);
		}; break;

		default:
		{
			NetPDLDecoderFlags|= (nbDECODER_GENERATEPDML_COMPLETE | nbDECODER_GENERATEPSML |
								nbDECODER_KEEPALLPSML | nbDECODER_KEEPALLPDML);
		}; break;
	}

	Decoder= nbAllocatePacketDecoder(NetPDLDecoderFlags, ErrBuf, sizeof(ErrBuf));
	if (Decoder == NULL)
	{
		printf("Error creating the NetPDLParser: %s.\n", ErrBuf);
		return nbFAILURE;
	}

	// Let's set the source file
	if (CaptureFileName)
		strcpy(Buffer, CaptureFileName);
	else
		strcpy(Buffer, "samplecapturedump.acp");

	if ((PcapPacketDumpFile= nbAllocatePacketDumpFilePcap(ErrBuf, sizeof(ErrBuf))) == NULL)
	{
		printf("Error creating the PcapPacketDumpFile: %s.\n", ErrBuf);
		return nbFAILURE;
	}

	//if (PcapPacketDumpFile->OpenDumpFile(Buffer, 0) == nbFAILURE)
	//{
	//	printf("%s", PcapPacketDumpFile->GetLastError());
	//	return nbFAILURE;
	//}
	if (PcapPacketDumpFile->OpenDumpFile(Buffer, 1) == nbFAILURE)
	{
		printf("%s", PcapPacketDumpFile->GetLastError());
		return nbFAILURE;
	}


	// Get the PacketDecoderVars; let's do the check, although it is not really needed
	if ((PacketDecoderVars= Decoder->GetPacketDecoderVars()) == NULL)
	{
		printf("Error: cannot get an instance of the nbPacketDecoderVars class.\n");
		return nbFAILURE;
	}

	// Set the appropriate NetPDL configuration variables
	PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames);

	if (PcapPacketDumpFile->GetLinkLayerType(LinkLayerType) == nbFAILURE)
	{
		printf("%s", PcapPacketDumpFile->GetLastError());
		return nbFAILURE;
	}

	nbPDMLReader *PDMLReader;
	PDMLReader = Decoder->GetPDMLReader();

	printf("\nStarting the file processing...\n\n");

	CMeasurement ElapsedTime;
	ElapsedTime.Start();

	while (1)
	{
	int RetVal;
	struct pcap_pkthdr* PktHeader;
	const unsigned char* PktData;

		RetVal= PcapPacketDumpFile->GetNextPacket(&PktHeader, &PktData);
//		RetVal= PcapPacketDumpFile->GetPacket(PacketCounter, &PktHeader, &PktData);

		if (RetVal == nbFAILURE)
		{
			printf("%s", PcapPacketDumpFile->GetLastError());
			return nbFAILURE;
		}

		// EOF
		if (RetVal == nbWARNING)
			break;

		// Decode packet
		if (Decoder->DecodePacket(LinkLayerType, PacketCounter, PktHeader, PktData) == nbFAILURE)
		{
			printf("\nError decoding a packet %s\n\n", Decoder->GetLastError());
			// Let's break and save what we've done so far
			break;
		}

		_nbPDMLPacket * curr_packet;
		curr_packet = new _nbPDMLPacket;
		printf("step 1\n");
	        PDMLReader->GetCurrentPacket(&curr_packet);
		printf("step 2\n");
	        _nbPDMLProto * proto;
	        _nbPDMLField * field;

        	proto = curr_packet->FirstProto;
		printf("step 3\n");

        	printf("\nPACKET LEN: %ld ",curr_packet->Length);

//		list_t *pktout;

//		packet_out_t * pktout;

		printf("step 4\n");

//		pktout = (list_t*) malloc(sizeof(list_t));
//		list_t_init(pktout);

//		pktout = (packet_out_t*) malloc(sizeof(packet_out_t));
//		list_t_init(&pktout->field.node);

		printf("step 5\n");
	        while (1)
        	{
               		printf("%s\n",*proto);
               		field = proto->FirstField;
                	while(1)
                	{

				printf("\nfield position %ld,  %s :",field->Position,*field);
	                        if(field->LongName[0]<58 && field->LongName[0]>47)
	                        {
		                        int i,pow;
	                                uint32_t type;
	                                uint8_t size;
					packet_out_t * pktout;
			                pktout = (packet_out_t*) malloc(sizeof(packet_out_t));

	                                packet_field_t *new_field;
	                                new_field = (packet_field_t *)malloc(sizeof(packet_field_t));
	                                for (type=0,i=0,pow=100;i<3;i++,pow = (pow==1 ? pow : pow/10))
	        	                        type = type + (pow*(field->LongName[i]-48));
		                        
					size = field->Size;
	                                pktout->header = NXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),size); 
	                                printf("\n LongName: %d",pktout->header);
	                                new_field->value = (uint8_t*) malloc(field->Size);
	                                memcpy(new_field->value,(PktData + field->Position),field->Size);

					packet_out_t *iter;
					bool done=0;
					printf("\n 1");
//					HMAP_FOR_EACH_WITH_HASH(iter,packet_out_t, hmap_node, hash_int(pktout->header,0),&all_packet_fields)
					HMAP_FOR_EACH(iter,packet_out_t, hmap_node,&all_packet_fields)
					{
						printf("\nHeader: %d",iter->header);
						if(iter->header == pktout->header)
						{
							printf("\n Adding entry to existing Hash Map");
							list_t_push_back(&iter->field,&new_field->node);
							done=1;
							break;
						}
					}

					if (!done)
					{
						list_t_init(&pktout->field);
						printf("\nNew Hash Map");
	                                	list_t_push_back(&pktout->field,&new_field->node);
//	                                	memcpy(&pktout->field,new_field, sizeof(new_field));  
	                                	hmap_insert(&all_packet_fields, &pktout->hmap_node,
		                        	hash_int(pktout->header, 0));
					}
					done =0;

				}
/*                       		printf("\nfield position %ld,  %s :",field->Position,*field);
                        	if(field->LongName[0]<58 && field->LongName[0]>47)
				{
					int i,pow;
						
	                        	packet_out_t *new_field;
	                        	new_field = (packet_out_t *)malloc(sizeof(packet_out_t));
        	        	        for (new_field->type=0,i=0,pow=100;i<3;i++,pow = (pow==1 ? pow : pow/10))
                		                new_field->type = new_field->type + (pow*(field->LongName[i]-48));
        	               	 	new_field->length = field->Size;
					printf("\n LongName: %d",new_field->type);	
                        		new_field->value = (uint8_t*) malloc(field->Size);
                	        	memcpy(new_field->value,(PktData + field->Position),field->Size);
		       	                list_t_push_back(pktout,&new_field->node);
				}
*/

	                        if(field->NextField == NULL && field->ParentField == NULL)
        	                {
					printf("\nbreaking");
                        	        break;
                       	 	}
	                        else if (field->NextField == NULL && field->ParentField != NULL)
        	                {
                	                field = field->ParentField;
                        	        printf("\nParent");
	                        }
        	                else if (!field->NextField->isField)
                	        {
                        	        printf("\nblock : %s",*field->NextField);
                                	field = field->NextField->FirstChild;
	                        }
        	                else
                	        {
                        	        printf("\n next field: %s ",*field->NextField);
                                	field = field->NextField;
	                        }
	
        	        }

                	printf("\n");
	                if (proto->NextProto == NULL)
        	        {
	                        break;
        	        }
                	proto = proto->NextProto;
	        }

                packet_out_t *fields;

//		fields = (packet_out_t *)malloc(sizeof(packet_out_t));

		HMAP_FOR_EACH (fields,packet_out_t, hmap_node,&all_packet_fields){
			if(fields != NULL)
			{
				printf("\nfield: %d    | size: %d     | ",NXM_TYPE(fields->header),NXM_LENGTH(fields->header));
				packet_field_t *iter;
				int count=0;
				LIST_T_FOR_EACH(iter, packet_field_t, node, &fields->field)
				{
			                int x;
					printf("\n%d          ",count);
					count++;
					
        			        for (x=0;x<NXM_LENGTH(fields->header);x++)
	                		{
						printf("%02X",iter->value[x]);
	                		}
				}
			}
		}

/*
                LIST_T_FOR_EACH(fields, packet_out_t, node, pktout){
                	printf("\nfield: %d    | size: %d     | ",fields->type,fields->length);
	                int x;
        	        for (x=0;x<fields->length;x++)
                	{
				printf("%02X",fields->value[x]);
	                }
                }

*/
                printf("\n");



#ifdef _DEBUG
		// In case we're in debug mode, let's print always the packet number
		// This is useful to check that the processing is going on (i.e. that the packet decoder
		// isn't hanging up in some infinite loop)
//		printf("%d ", PacketCounter);
#else
		// In case none of these define are active, let's print the packet number
		// These defines are often used to make performance measurement, hence we should
		// avoid any un-necessary overhead such as printing something on screen
		//if ((!DecodingOnly) && (!CompleteDecodingOnly))
			//printf("%d ", PacketCounter);
#endif

		PacketCounter++;
	}

	ElapsedTime.EndAndPrint();

	printf("\nRead and decoded %d packets.\n\n", PacketCounter - 1);


	// Dump files to disk
	if ((DecodingType != DECODE_NOSAVE) && (DecodingType != DECODEALL_NOSAVE))
	{
		printf("\nDumping PDML file on disk: file %s\n", PDMLFILE);

		nbPDMLReader *PDMLReader= Decoder->GetPDMLReader();
		if (PDMLReader == NULL)
		{
			printf("Error getting PDMLReader: %s\n", Decoder->GetLastError() );
			return nbFAILURE;
		}

		if (PDMLReader->SaveDocumentAs(PDMLFILE) == nbFAILURE)
		{
			printf("Error dumping PDML file on disk: %s\n", PDMLReader->GetLastError());
			return nbFAILURE;
		}


		if (DecodingType != DECODE_AND_SAVE)
		{
			printf("\nDumping PSML file on disk: file %s\n", PSMLFILE);

			nbPSMLReader *PSMLReader= Decoder->GetPSMLReader();
			if (PSMLReader == NULL)
			{
				printf("Error getting PSMLReader: %s\n", Decoder->GetLastError() );
				return nbFAILURE;
			}

			if (PSMLReader->SaveDocumentAs(PSMLFILE) == nbFAILURE)
			{
				printf("Error dumping PSML file on disk: %s\n", PSMLReader->GetLastError());
				return nbFAILURE;
			}
		}
	}

	// delete the decoder
	nbDeallocatePacketDecoder(Decoder);
	nbDeallocatePacketDumpFilePcap(PcapPacketDumpFile);

	nbCleanup();

	return nbSUCCESS;
}
