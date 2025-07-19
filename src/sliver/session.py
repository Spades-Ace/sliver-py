"""
    Sliver Implant Framework
    Copyright (C) 2022  Bishop Fox

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
from typing import List, Union

import grpc

from .interactive import BaseInteractiveCommands
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub
from .protobuf import client_pb2, sliver_pb2, common_pb2

import asyncio , binascii

def _hexdump(b: bytes, maxlen: int = 64) -> str:
    return binascii.hexlify(b[:maxlen], b" ").decode()

async def _socks_request_iterator(queue: asyncio.Queue):
    """
    Async generator that yields SocksData frames placed in `queue`.
    Put None in the queue to signal shutdown.
    """
    while True:
        item = await queue.get()
        if item is None:          # sentinel -> close stream
            break
        yield item


class BaseSession:
    """Base class for Session objects.

    :param session: Session protobuf.
    :type session: client_pb2.Session
    :param channel: A gRPC channel.
    :type channel: grpc.Channel
    :param timeout: Timeout in seconds
    :type timeout: int, optional
    """

    def __init__(
        self,
        session: client_pb2.Session,
        channel: grpc.aio.Channel,
        timeout: int = 60,
    ):
        self._channel = channel
        self._session = session
        self._stub = SliverRPCStub(channel)
        self.timeout = timeout

    def _request(self, pb):
        """
        Set request attributes based on current session, I'd prefer to return a generic Request
        object, but protobuf for whatever reason doesn't let you assign this type of field directly.

        `pb` in this case is any protobuf message with a .Request field.

        :param pb: A protobuf request object.
        """
        pb.Request.SessionID = self._session.ID
        pb.Request.Timeout = self.timeout - 1
        return pb

    @property
    def session_id(self) -> str:
        """Session ID"""
        return self._session.ID

    @property
    def name(self) -> str:
        """Session name"""
        return self._session.Name

    @property
    def hostname(self) -> str:
        """Hostname"""
        return self._session.Hostname

    @property
    def uuid(self) -> str:
        """Session UUID"""
        return self._session.UUID

    @property
    def username(self) -> str:
        """Username"""
        return self._session.Username

    @property
    def uid(self) -> str:
        """User ID"""
        return self._session.UID

    @property
    def gid(self) -> str:
        """Group ID"""
        return self._session.GID

    @property
    def os(self) -> str:
        """Operating system"""
        return self._session.OS

    @property
    def arch(self) -> str:
        """Architecture"""
        return self._session.Arch

    @property
    def transport(self) -> str:
        """Transport Method"""
        return self._session.Transport

    @property
    def remote_address(self) -> str:
        """Remote address"""
        return self._session.RemoteAddress

    @property
    def pid(self) -> int:
        """Process ID"""
        return self._session.PID

    @property
    def filename(self) -> str:
        """Implant filename"""
        return self._session.Filename

    @property
    def last_checkin(self) -> int:
        """Last check in"""
        return self._session.LastCheckin

    @property
    def active_c2(self) -> str:
        """Active C2"""
        return self._session.ActiveC2

    @property
    def version(self) -> str:
        """Version"""
        return self._session.Version

    @property
    def is_dead(self) -> bool:
        """Is dead"""
        return self._session.IsDead

    @property
    def reconnect_interval(self) -> int:
        """Reconnect interval"""
        return self._session.ReconnectInterval

    @property
    def proxy_url(self) -> str:
        """Proxy URL"""

        return self._session.ProxyURL


class InteractiveSession(BaseSession, BaseInteractiveCommands):
    """Session only commands"""

    async def pivot_listeners(self) -> List[sliver_pb2.PivotListener]:
        """List C2 pivots

        :return: Protobuf PivotListener list
        :rtype: List[sliver_pb2.PivotListener]
        """
        pivots = await self._stub.PivotSessionListeners(
            self._request(sliver_pb2.PivotListenersReq()), timeout=self.timeout
        )
        return list(pivots.Listeners)

    async def start_service(
        self, name: str, description: str, exe: str, hostname: str, arguments: str
    ) -> sliver_pb2.ServiceInfo:
        """Create and start a Windows service (Windows only)

        :param name: Name of the service
        :type name: str
        :param description: Service description
        :type description: str
        :param exe: Path to the service .exe file
        :type exe: str
        :param hostname: Hostname
        :type hostname: str
        :param arguments: Arguments to start the service with
        :type arguments: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        """
        svc = sliver_pb2.StartServiceReq()
        svc.ServiceName = name
        svc.ServiceDescription = description
        svc.BinPath = exe
        svc.Hostname = hostname
        svc.Arguments = arguments
        return await self._stub.StartService(self._request(svc), timeout=self.timeout)

    async def stop_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        """Stop a Windows service (Windows only)

        :param name: Name of the servie
        :type name: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        """
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return await self._stub.StopService(self._request(svc), timeout=self.timeout)

    async def remove_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        """Remove a Windows service (Windows only)

        :param name: Name of the service
        :type name: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        """
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return await self._stub.RemoveService(self._request(svc), timeout=self.timeout)

    async def backdoor(
        self, remote_path: str, profile_name: str
    ) -> sliver_pb2.Backdoor:
        """Backdoor a remote binary by injecting a Sliver payload into the executable using a code cave

        :param remote_path: Remote path to an executable to backdoor
        :type remote_path: str
        :param profile_name: Implant profile name to inject into the binary
        :type profile_name: str
        :return: Protobuf Backdoor object
        :rtype: sliver_pb2.Backdoor
        """
        backdoor = sliver_pb2.BackdoorReq()
        backdoor.FilePath = remote_path
        backdoor.ProfileName = profile_name
        return await self._stub.Backdoor(self._request(backdoor), timeout=self.timeout)
    
    async def interactive_session_close(self) -> sliver_pb2.CloseSession:
        """
        Close the interactive session by calling the CloseSession RPC.
        """
        pb = sliver_pb2.CloseSession()
        req = self._request(pb)
        resp: sliver_pb2.CloseSession = await self._stub.CloseSession(req,timeout=self.timeout)
        return resp
    
    async def socks5_start(self,bind_addr: str = "127.0.0.1",bind_port: int = 1080,username: str = "",password: str = "",rcv_chunk: int = 4096,):
        """
        SOCKS-5 pivot listener with *very* verbose debugging.
        """

        async def _handle_local(reader: asyncio.StreamReader,writer: asyncio.StreamWriter):

            peer = writer.get_extra_info("peername")
            logging.debug("NEW  client %s", peer)

            # ------ open gRPC SocksProxy stream ----------------------------------
            send_q: asyncio.Queue = asyncio.Queue()
            stream = self._stub.SocksProxy(_socks_request_iterator(send_q))

            async def _rx():                         # implant → client
                try:
                    async for sd in stream:
                        logging.debug("I→P recv  seq=%s len=%s close=%s  %s",sd.Sequence, len(sd.Data), sd.CloseConn,_hexdump(sd.Data))
                        if sd.CloseConn:
                            writer.close(); return
                        writer.write(sd.Data)
                        await writer.drain()
                except grpc.aio.AioRpcError as e:
                    if e.code() != grpc.StatusCode.UNAVAILABLE:
                        logging.error("gRPC error: %s", e)

            asyncio.create_task(_rx())

            # ------ create tunnel on Sliver --------------------------------------
            rsp = await self._stub.CreateSocks(sliver_pb2.Socks(SessionID=self._session.ID), timeout=self.timeout)
            tunnel_id = rsp.TunnelID
            req_meta  = common_pb2.Request(SessionID=rsp.SessionID)

            # ------ first read / first frame -------------------------------------
            seq = 0
            first = await reader.read(rcv_chunk)
            if not first:
                writer.close(); await writer.wait_closed(); await send_q.put(None)
                return

            await send_q.put(
                sliver_pb2.SocksData(
                    TunnelID=tunnel_id,
                    Username=username,
                    Password=password,
                    Request=req_meta,
                    Data=first,
                    Sequence=seq,
                )
            )
            logging.debug("P→I send  seq=%s len=%s close=False  %s",
                        seq, len(first), _hexdump(first))
            seq += 1

            # ------ relay loop ----------------------------------------------------
            try:
                while True:
                    data = await reader.read(rcv_chunk)
                    if not data:
                        logging.debug("EOF client %s", peer)
                        await send_q.put(
                            sliver_pb2.SocksData(
                                TunnelID=tunnel_id,
                                Username=username,
                                Password=password,
                                Request=req_meta,
                                CloseConn=True,
                            )
                        )
                        logging.debug("P→I send  CLOSE")
                        break

                    logging.debug("C→P data  %s", _hexdump(data))
                    await send_q.put(
                        sliver_pb2.SocksData(
                            TunnelID=tunnel_id,
                            Username=username,
                            Password=password,
                            Request=req_meta,
                            Data=data,
                            Sequence=seq,
                        )
                    )
                    logging.debug("P→I send  seq=%s len=%s close=False",
                                seq, len(data))
                    seq += 1
            finally:
                writer.close()
                await writer.wait_closed()
                await send_q.put(None)        # close iterator → gRPC stream
                logging.debug("CLOSE tunnel %s", tunnel_id)

        # ------ launch listener ---------------------------------------------------
        server = await asyncio.start_server(_handle_local, bind_addr, bind_port)
        host, port = server.sockets[0].getsockname()[:2]
        print(f"[+] SOCKS-5 listener up on {host}:{port}  (Ctrl-C to stop)")
        return server

    async def startpivot(self,port) -> sliver_pb2.PivotStartListenerReq:
        """
        Starts a pivot listener on the specified port.
        :param port: Port to bind the listener to
        :type port: int
        :return: Protobuf PivotStartListenerReq object
        :rtype: sliver_pb2.PivotStartListenerReq
        """
        
        # 1) Instantiate the PivotStartListenerReq protobuf
        pb = sliver_pb2.PivotStartListenerReq()
        pb.BindAddress = port

        # 2) Set the request attributes based on the current session
        req = self._request(pb)

        # 3) Fire the gRPC
        resp: sliver_pb2.PivotStartListenerReq = await self._stub.PivotStartListener(
            req,
            timeout=self.timeout
        )

        # 4) Return the fully-populated response object
        return resp
